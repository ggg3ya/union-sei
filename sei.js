import ethers from 'ethers';
import readlineSync from 'readline-sync';
import axios from 'axios';

console.log(`Using ethers version: ${ethers.version}`);

function isValidHex(str) {
  return /^0x[0-9a-fA-F]*$/.test(str) && str.length % 2 === 0;
}

const SEPOLIA_RPC = 'https://eth-sepolia.public.blastapi.io';
const SEPOLIA_CHAIN_ID = 11155111;
const USDC_ADDRESS = '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238';
const WETH_ADDRESS_SEPOLIA = '0x7b79995e5f793a07bc00c21412e50ecae098e7f9'; 

const HOLESKY_RPC = 'https://ethereum-holesky-rpc.publicnode.com';
const HOLESKY_CHAIN_ID = 17000;
const WETH_ADDRESS = '0x94373a4919B3240D86eA41593D5eBa789FEF3848';
const BRIDGE_CONTRACT = '0x5FbE74A283f7954f10AA04C2eDf55578811aeb03';

const UCS03_ABI = [
  {
    inputs: [
      { internalType: 'uint32', name: 'channelId', type: 'uint32' },
      { internalType: 'uint64', name: 'timeoutHeight', type: 'uint64' },
      { internalType: 'uint64', name: 'timeoutTimestamp', type: 'uint64' },
      { internalType: 'bytes32', name: 'salt', type: 'bytes32' },
      {
        components: [
          { internalType: 'uint8', name: 'version', type: 'uint8' },
          { internalType: 'uint8', name: 'opcode', type: 'uint8' },
          { internalType: 'bytes', name: 'operand', type: 'bytes' },
        ],
        internalType: 'struct Instruction',
        name: 'instruction',
        type: 'tuple',
      },
    ],
    name: 'send',
    outputs: [],
    stateMutability: 'nonpayable',
    type: 'function',
  },
];

const ERC20_ABI = [
  'function balanceOf(address account) view returns (uint256)',
  'function allowance(address owner, address spender) view returns (uint256)',
  'function approve(address spender, uint256 amount) returns (bool)',
  'function deposit() payable',
];

const sepoliaProvider = new ethers.providers.JsonRpcProvider(SEPOLIA_RPC);
const holeskyProvider = new ethers.providers.JsonRpcProvider(HOLESKY_RPC);

const privateKey = readlineSync.question('Enter your private key: ', { hideEchoBack: true });
const sepoliaWallet = new ethers.Wallet(privateKey).connect(sepoliaProvider);
const holeskyWallet = new ethers.Wallet(privateKey).connect(holeskyProvider);
const userAddress = sepoliaWallet.address;

const usdcAmount = parseFloat(0.1);
const wethAmount = parseFloat(0.01);
const loopCount = parseInt(readlineSync.question('Enter number of bridge loops: '));

if (isNaN(usdcAmount) || usdcAmount <= 0) throw new Error('Invalid USDC amount');
if (isNaN(wethAmount) || wethAmount <= 0) throw new Error('Invalid WETH amount');
if (isNaN(loopCount) || loopCount <= 0) throw new Error('Invalid loop count');

const usdcAmountWei = ethers.utils.parseUnits(usdcAmount.toString(), 6);
const wethAmountWei = ethers.utils.parseUnits(wethAmount.toString(), 18);
const wethThresholdWei = ethers.utils.parseUnits('0.01', 18);
const SALT = ethers.utils.hexlify(ethers.utils.randomBytes(32));

async function checkBalance(provider, tokenAddress, userAddress, amountWei, decimals, tokenSymbol) {
  const tokenContract = new ethers.Contract(tokenAddress, ERC20_ABI, provider);
  const balance = await tokenContract.balanceOf(userAddress);
  console.log(`${tokenSymbol} Balance: ${ethers.utils.formatUnits(balance, decimals)} ${tokenSymbol}`);
  return { balance, sufficient: balance.gte(amountWei) };
}

async function checkEthBalance(provider, userAddress, network, requiredEthWei = ethers.utils.parseEther('0.01')) {
  const balance = await provider.getBalance(userAddress);
  console.log(`${network} ETH Balance: ${ethers.utils.formatEther(balance)} ETH`);
  return { balance, sufficient: balance.gte(requiredEthWei) };
}

async function checkApproval(provider, tokenAddress, userAddress, spender, amountWei, tokenSymbol) {
  const contract = new ethers.Contract(tokenAddress, ERC20_ABI, provider);
  const allowance = await contract.allowance(userAddress, spender);
  console.log(`Allowance for ${spender} (${tokenSymbol}): ${ethers.utils.formatUnits(allowance, tokenSymbol === 'USDC' ? 6 : 18)} ${tokenSymbol}`);
  return allowance.gte(amountWei);
}

async function approveToken(wallet, tokenAddress, spender, amountWei, tokenSymbol) {
  const contract = new ethers.Contract(tokenAddress, ERC20_ABI, wallet);
  const tx = await contract.approve(spender, amountWei, { gasLimit: 70000 });
  const receipt = await tx.wait();
  console.log(`${tokenSymbol} Approval TX Hash: ${tx.hash}`);
  return receipt.status === 1;
}

async function convertEthToWeth(wallet, wethAddress, amountWei) {
  const contract = new ethers.Contract(wethAddress, ERC20_ABI, wallet);
  const tx = await contract.deposit({ value: amountWei, gasLimit: 100000 });
  const receipt = await tx.wait();
  console.log(`ETH to WETH Conversion TX Hash: ${tx.hash}`);
  return receipt.status === 1;
}

async function pollPacketHash(txHash, retries = 50, intervalMs = 5000) {
  const headers = {
    accept: 'application/graphql-response+json, application/json',
    'content-type': 'application/json',
    origin: 'https://app.union.build',
    referer: 'https://app.union.build/',
    'user-agent': 'Mozilla/5.0',
  };
  const data = {
    query: `
      query ($submission_tx_hash: String!) {
        v2_transfers(args: {p_transaction_hash: $submission_tx_hash}) {
          packet_hash
        }
      }
    `,
    variables: {
      submission_tx_hash: txHash.startsWith('0x') ? txHash : `0x${txHash}`,
    },
  };

  for (let i = 0; i < retries; i++) {
    try {
      const res = await axios.post('https://graphql.union.build/v1/graphql', data, { headers });
      const result = res.data?.data?.v2_transfers;
      if (result && result.length > 0 && result[0].packet_hash) {
        return result[0].packet_hash;
      }
    } catch (e) {
      console.error(`Packet error: ${e.message}`);
    }
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
  console.warn('Failed to retrieve packet hash after retries');
  return null;
}

async function bridgeUsdcSepoliaToHolesky(amountWei) {
  console.log('Checking balances on Sepolia...');
  const { sufficient: hasUsdc } = await checkBalance(sepoliaProvider, USDC_ADDRESS, userAddress, amountWei, 6, 'USDC');
  const { sufficient: hasEth } = await checkEthBalance(sepoliaProvider, userAddress, 'Sepolia');
  if (!hasUsdc) {
    console.log('Insufficient USDC balance');
    return false;
  }
  if (!hasEth) {
    console.log('Insufficient ETH balance for gas');
    return false;
  }

  const isApproved = await checkApproval(sepoliaProvider, USDC_ADDRESS, userAddress, BRIDGE_CONTRACT, amountWei, 'USDC');
  if (!isApproved) {
    console.log('Approving USDC on Sepolia...');
    const approvalSuccess = await approveToken(sepoliaWallet, USDC_ADDRESS, BRIDGE_CONTRACT, amountWei, 'USDC');
    if (!approvalSuccess) {
      console.log('Approval failed on Sepolia');
      return false;
    }
  } else {
    console.log('USDC already approved on Sepolia');
  }

  const contract = new ethers.Contract(BRIDGE_CONTRACT, UCS03_ABI, sepoliaWallet);
  const addressHex = userAddress.slice(2).toLowerCase();
  const channelId = 8;
  const timeoutHeight = 0;
  const now = BigInt(Date.now()) * 1_000_000n;
  const oneDayNs = 86_400_000_000_000n;
  const timeoutTimestamp = (now + oneDayNs).toString();
  const timestampNow = Math.floor(Date.now() / 1000);
  const salt = ethers.utils.solidityKeccak256(['address', 'uint256'], [userAddress, timestampNow]);

  const operand = '0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000027100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000027100000000000000000000000000000000000000000000000000000000000000014' +
    addressHex +
    '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000014' +
    addressHex +
    '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000141c7d4b196cb0c7b01d743fbc6116a902379c72380000000000000000000000000000000000000000000000000000000000000000000000000000000000000004555344430000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000045553444300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001457978bfe465ad9b1c0bf80f6c1539d300705ea50000000000000000000000000';

  const instruction = {
    version: 0,
    opcode: 2,
    operand,
  };

  let data;
  const iface = new ethers.utils.Interface(UCS03_ABI);
  try {
    data = iface.encodeFunctionData('send', [channelId, timeoutHeight, timeoutTimestamp, salt, instruction]);
  } catch (error) {
    console.error('Failed to encode send function data (Sepolia):', error);
    return false;
  }

  console.log(`Sepolia to Holesky (send) data length: ${data.length}`);
  console.log(`Sepolia to Holesky (send) data valid hex: ${isValidHex(data)}`);

  try {
    const simulationResult = await sepoliaProvider.call({ to: BRIDGE_CONTRACT, data, from: userAddress });
    console.log('Simulation successful (Sepolia send), result:', simulationResult);
  } catch (error) {
    console.error('Simulation failed (Sepolia send):', error);
    if (error.data) {
      try {
        const decodedError = iface.parseError(error.data);
        console.error('Decoded revert reason:', decodedError.name, decodedError.args);
      } catch (parseError) {
        console.error('Failed to decode revert reason:', parseError);
      }
    }
    return false;
  }

  const tx = { to: BRIDGE_CONTRACT, data, chainId: SEPOLIA_CHAIN_ID };
  try {
    const txResponse = await sepoliaWallet.sendTransaction(tx);
    console.log(`Sepolia Transaction sent, hash: ${txResponse.hash}`);
    const receipt = await txResponse.wait();
    console.log(`Sepolia to Holesky Bridge TX Hash: ${txResponse.hash}`);
    if (receipt.status === 0) {
      console.error('Sepolia Transaction reverted');
      return false;
    }
    const packetHash = await pollPacketHash(txResponse.hash);
    if (packetHash) {
      console.log(`Packet Submitted: https://app.union.build/explorer/transfers/${packetHash}`);
    }
    return true;
  } catch (error) {
    console.error('Sepolia Transaction failed:', error);
    return false;
  }
}

async function bridgeWethSepoliaToHolesky(amountWei) {
  console.log('Checking balances on Sepolia...');
  const { balance: wethBalance, sufficient: hasWeth } = await checkBalance(sepoliaProvider, WETH_ADDRESS_SEPOLIA, userAddress, amountWei, 18, 'WETH');
  const { balance: ethBalance, sufficient: hasEth } = await checkEthBalance(sepoliaProvider, userAddress, 'Sepolia', ethers.utils.parseEther('0.01').add(amountWei));

  if (wethBalance.lt(wethThresholdWei)) {
    console.log('WETH balance below 0.01 WETH, attempting to convert ETH to WETH...');
    if (!hasEth) {
      console.log('Insufficient ETH balance for conversion and gas');
      return false;
    }
    if (ethBalance.lt(amountWei)) {
      console.log('Insufficient ETH balance to convert to required WETH amount');
      return false;
    }

    console.log(`Converting ${ethers.utils.formatEther(amountWei)} ETH to WETH...`);
    const conversionSuccess = await convertEthToWeth(sepoliaWallet, WETH_ADDRESS_SEPOLIA, amountWei);
    if (!conversionSuccess) {
      console.log('ETH to WETH conversion failed');
      return false;
    }

    const { sufficient: hasWethAfterConversion } = await checkBalance(sepoliaProvider, WETH_ADDRESS_SEPOLIA, userAddress, amountWei, 18, 'WETH');
    if (!hasWethAfterConversion) {
      console.log('Insufficient WETH balance after conversion');
      return false;
    }

    console.log('Approving WETH on Sepolia after conversion...');
    const approvalSuccess = await approveToken(sepoliaWallet, WETH_ADDRESS_SEPOLIA, BRIDGE_CONTRACT, amountWei, 'WETH');
    if (!approvalSuccess) {
      console.log('WETH approval failed after conversion');
      return false;
    }
  } else if (!hasWeth) {
    console.log('Insufficient WETH balance and above threshold, cannot bridge');
    return false;
  } else if (!hasEth) {
    console.log('Insufficient ETH balance for gas');
    return false;
  }

  const isApproved = await checkApproval(sepoliaProvider, WETH_ADDRESS_SEPOLIA, userAddress, BRIDGE_CONTRACT, amountWei, 'WETH');
  if (!isApproved) {
    console.log('Approving WETH on Sepolia...');
    const approvalSuccess = await approveToken(sepoliaWallet, WETH_ADDRESS_SEPOLIA, BRIDGE_CONTRACT, amountWei, 'WETH');
    if (!approvalSuccess) {
      console.log('Approval failed on Sepolia');
      return false;
    }
  } else {
    console.log('WETH already approved on Sepolia');
  }

  const contract = new ethers.Contract(BRIDGE_CONTRACT, UCS03_ABI, sepoliaWallet);
  const addressHex = userAddress.slice(2).toLowerCase();
  const wethAddressHex = WETH_ADDRESS_SEPOLIA.slice(2).toLowerCase();
  const bridgeAddressHex = 'b476983cc7853797fc5adc4bcad39b277bc79656';
  const channelId = 8;
  const timeoutHeight = 0;
  const now = BigInt(Date.now()) * 1_000_000n;
  const oneDayNs = 86_400_000_000_000n;
  const timeoutTimestamp = (now + oneDayNs).toString();
  const timestampNow = Math.floor(Date.now() / 1000);
  const salt = ethers.utils.solidityKeccak256(['address', 'uint256'], [userAddress, timestampNow]);

  const sepoliaOperand = '0x' +
    '0000000000000000000000000000000000000000000000000000000000000020' +
    '0000000000000000000000000000000000000000000000000000000000000001' +
    '0000000000000000000000000000000000000000000000000000000000000020' +
    '0000000000000000000000000000000000000000000000000000000000000001' +
    '0000000000000000000000000000000000000000000000000000000000000003' +
    '0000000000000000000000000000000000000000000000000000000000000060' +
    '00000000000000000000000000000000000000000000000000000000000002c0' +
    '0000000000000000000000000000000000000000000000000000000000000140' +
    '0000000000000000000000000000000000000000000000000000000000000180' +
    '00000000000000000000000000000000000000000000000000000000000001c0' +
    '00000000000000000000000000000000000000000000000000005af3107a4000' +
    '0000000000000000000000000000000000000000000000000000000000000200' +
    '0000000000000000000000000000000000000000000000000000000000000240' +
    '0000000000000000000000000000000000000000000000000000000000000012' +
    '0000000000000000000000000000000000000000000000000000000000000000' +
    '0000000000000000000000000000000000000000000000000000000000000280' +
    '00000000000000000000000000000000000000000000000000005af3107a4000' +
    '0000000000000000000000000000000000000000000000000000000000000014' +
    addressHex.padEnd(64, '0') +
    '0000000000000000000000000000000000000000000000000000000000000014' +
    addressHex.padEnd(64, '0') +
    '0000000000000000000000000000000000000000000000000000000000000014' +
    wethAddressHex.padEnd(64, '0') +
    '0000000000000000000000000000000000000000000000000000000000000004' +
    '5745544800000000000000000000000000000000000000000000000000000000' +
    '000000000000000000000000000000000000000000000000000000000000000d' +
    '5772617070656420457468657200000000000000000000000000000000000000' +
    '0000000000000000000000000000000000000000000000000000000000000014' +
    bridgeAddressHex.padEnd(64, '0');

  const instruction = {
    version: 0,
    opcode: 2,
    operand: sepoliaOperand
  };

  let data;
  const iface = new ethers.utils.Interface(UCS03_ABI);
  try {
    data = iface.encodeFunctionData('send', [channelId, timeoutHeight, timeoutTimestamp, salt, instruction]);
  } catch (error) {
    console.error('Failed to encode send function data (Sepolia):', error);
    return false;
  }

  console.log(`Sepolia to Holesky (send) data length: ${data.length}`);
  console.log(`Sepolia to Holesky (send) data valid hex: ${isValidHex(data)}`);

  try {
    const simulationResult = await sepoliaProvider.call({ to: BRIDGE_CONTRACT, data, from: userAddress });
    console.log('Simulation successful (Sepolia send), result:', simulationResult);
  } catch (error) {
    console.error('Simulation failed (Sepolia send):', error);
    if (error.data) {
      try {
        const decodedError = iface.parseError(error.data);
        console.error('Decoded revert reason:', decodedError.name, decodedError.args);
      } catch (parseError) {
        console.error('Failed to decode revert reason:', parseError);
      }
    }
    return false;
  }

  const tx = { to: BRIDGE_CONTRACT, data, chainId: SEPOLIA_CHAIN_ID };
  try {
    const txResponse = await sepoliaWallet.sendTransaction(tx);
    console.log(`Sepolia Transaction sent, hash: ${txResponse.hash}`);
    const receipt = await txResponse.wait();
    console.log(`Sepolia to Holesky Bridge TX Hash: ${txResponse.hash}`);
    if (receipt.status === 0) {
      console.error('Sepolia Transaction reverted');
      return false;
    }
    const packetHash = await pollPacketHash(txResponse.hash);
    if (packetHash) {
      console.log(`Packet Submitted: https://app.union.build/explorer/transfers/${packetHash}`);
    }
    return true;
  } catch (error) {
    console.error('Sepolia Transaction failed:', error);
    return false;
  }
}

async function bridgeWethHoleskyToSepolia(amountWei) {
  console.log('Checking balances on Holesky...');
  const { balance: wethBalance, sufficient: hasWeth } = await checkBalance(holeskyProvider, WETH_ADDRESS, userAddress, amountWei, 18, 'WETH');
  const { balance: ethBalance, sufficient: hasEth } = await checkEthBalance(holeskyProvider, userAddress, 'Holesky', ethers.utils.parseEther('0.01').add(amountWei));

  if (wethBalance.lt(wethThresholdWei)) {
    console.log('WETH balance below 0.01 WETH, attempting to convert ETH to WETH...');
    if (!hasEth) {
      console.log('Insufficient ETH balance for conversion and gas');
      return false;
    }
    if (ethBalance.lt(amountWei)) {
      console.log('Insufficient ETH balance to convert to required WETH amount');
      return false;
    }

    console.log(`Converting ${ethers.utils.formatEther(amountWei)} ETH to WETH...`);
    const conversionSuccess = await convertEthToWeth(holeskyWallet, WETH_ADDRESS, amountWei);
    if (!conversionSuccess) {
      console.log('ETH to WETH conversion failed');
      return false;
    }

    const { sufficient: hasWethAfterConversion } = await checkBalance(holeskyProvider, WETH_ADDRESS, userAddress, amountWei, 18, 'WETH');
    if (!hasWethAfterConversion) {
      console.log('Insufficient WETH balance after conversion');
      return false;
    }

    console.log('Approving WETH on Holesky after conversion...');
    const approvalSuccess = await approveToken(holeskyWallet, WETH_ADDRESS, BRIDGE_CONTRACT, amountWei, 'WETH');
    if (!approvalSuccess) {
      console.log('WETH approval failed after conversion');
      return false;
    }
  } else if (!hasWeth) {
    console.log('Insufficient WETH balance and above threshold, cannot bridge');
    return false;
  } else if (!hasEth) {
    console.log('Insufficient ETH balance for gas');
    return false;
  }

  const isApproved = await checkApproval(holeskyProvider, WETH_ADDRESS, userAddress, BRIDGE_CONTRACT, amountWei, 'WETH');
  if (!isApproved) {
    console.log('Approving WETH on Holesky...');
    const approvalSuccess = await approveToken(holeskyWallet, WETH_ADDRESS, BRIDGE_CONTRACT, amountWei, 'WETH');
    if (!approvalSuccess) {
      console.log('Approval failed on Holesky');
      return false;
    }
  } else {
    console.log('WETH already approved on Holesky');
  }

  const contract = new ethers.Contract(BRIDGE_CONTRACT, UCS03_ABI, holeskyWallet);
  const addressHex = userAddress.slice(2).toLowerCase();
  const wethAddressHex = WETH_ADDRESS.slice(2).toLowerCase();
  const bridgeAddressHex = '1a92b29dbc16e1ba9c02973fab1f7755a2786de1'; // Holesky bridge address (verify)
  const channelId = 2;
  const timeoutHeight = 0;
  const now = BigInt(Date.now()) * 1_000_000n;
  const oneDayNs = 86_400_000_000_000n;
  const timeoutTimestamp = (now + oneDayNs).toString();
  const timestampNow = Math.floor(Date.now() / 1000);
  const salt = ethers.utils.solidityKeccak256(['address', 'uint256'], [userAddress, timestampNow]);

  const holeskyOperand = '0x' +
  '0000000000000000000000000000000000000000000000000000000000000020' + 
  '0000000000000000000000000000000000000000000000000000000000000001' + 
  '0000000000000000000000000000000000000000000000000000000000000020' + 
  '0000000000000000000000000000000000000000000000000000000000000001' + 
  '0000000000000000000000000000000000000000000000000000000000000003' +
  '0000000000000000000000000000000000000000000000000000000000000060' + 
  '00000000000000000000000000000000000000000000000000000000000002c0' +
  '0000000000000000000000000000000000000000000000000000000000000140' + 
  '0000000000000000000000000000000000000000000000000000000000000180' + 
  '00000000000000000000000000000000000000000000000000000000000001c0' + 
  '00000000000000000000000000000000000000000000000000005af3107a4000' + 
  '0000000000000000000000000000000000000000000000000000000000000200' + 
  '0000000000000000000000000000000000000000000000000000000000000240' + 
  '0000000000000000000000000000000000000000000000000000000000000012' + 
  '0000000000000000000000000000000000000000000000000000000000000000' +
  '0000000000000000000000000000000000000000000000000000000000000280' + 
  '00000000000000000000000000000000000000000000000000005af3107a4000' + 
  '0000000000000000000000000000000000000000000000000000000000000014' + 
  addressHex.padEnd(64, '0') +                                         
  '0000000000000000000000000000000000000000000000000000000000000014' +
  addressHex.padEnd(64, '0') +                                         
  '0000000000000000000000000000000000000000000000000000000000000014' + 
  wethAddressHex.padEnd(64, '0') +                                     
  '0000000000000000000000000000000000000000000000000000000000000004' + 
  '5745544800000000000000000000000000000000000000000000000000000000' + 
  '000000000000000000000000000000000000000000000000000000000000000d' + 
  '5772617070656420457468657200000000000000000000000000000000000000' + 
  '0000000000000000000000000000000000000000000000000000000000000014' + 
  bridgeAddressHex.padEnd(64, '0');                                   


  const instruction = {
    version: 0,
    opcode: 2,
    operand: holeskyOperand, // Use holeskyOperand
  };

  let data;
  const iface = new ethers.utils.Interface(UCS03_ABI);
  try {
    data = iface.encodeFunctionData('send', [channelId, timeoutHeight, timeoutTimestamp, salt, instruction]);
  } catch (error) {
    console.error('Failed to encode send function data (Holesky):', error);
    return false;
  }

  console.log(`Holesky to Sepolia (send) data length: ${data.length}`);
  console.log(`Holesky to Sepolia (send) data valid hex: ${isValidHex(data)}`);

  try {
    const simulationResult = await holeskyProvider.call({ to: BRIDGE_CONTRACT, data, from: userAddress });
    console.log('Simulation successful (Holesky send), result:', simulationResult);
  } catch (error) {
    console.error('Simulation failed (Holesky send):', error);
    if (error.data) {
      try {
        const decodedError = iface.parseError(error.data);
        console.error('Decoded revert reason:', decodedError.name, decodedError.args);
      } catch (parseError) {
        console.error('Failed to decode revert reason:', parseError);
      }
    }
    return false;
  }

  const tx = { to: BRIDGE_CONTRACT, data, chainId: HOLESKY_CHAIN_ID };
  try {
    const txResponse = await holeskyWallet.sendTransaction(tx);
    console.log(`Holesky Transaction sent, hash: ${txResponse.hash}`);
    const receipt = await txResponse.wait();
    console.log(`Holesky to Sepolia Bridge TX Hash: ${txResponse.hash}`);
    if (receipt.status === 0) {
      console.error('Holesky Transaction reverted');
      return false;
    }
    const packetHash = await pollPacketHash(txResponse.hash);
    if (packetHash) {
      console.log(`Packet Submitted: https://app.union.build/explorer/transfers/${packetHash}`);
    }
    return true;
  } catch (error) {
    console.error('Holesky Transaction failed:', error);
    return false;
  }
}



async function main() {
  console.log(`Using salt: ${SALT}`);
  for (let i = 0; i < loopCount; i++) {
    console.log(`\nStarting bridge loop ${i + 1}/${loopCount}`);
    console.log('Bridging USDC from Sepolia to Holesky...');
    const sepoliaSuccess = await bridgeUsdcSepoliaToHolesky(usdcAmountWei);
    if (!sepoliaSuccess) {
      console.log('Sepolia to Holesky bridge failed');
      break;
    }

    await new Promise(resolve => setTimeout(resolve, 100000)); 
    console.log('Bridging WETH from Holesky to Sepolia...');
    const holeskySuccess = await bridgeWethHoleskyToSepolia(wethAmountWei);
    if (!holeskySuccess) {
      console.log('Holesky to Sepolia bridge failed');
      break;
    }
    await new Promise(resolve => setTimeout(resolve, 100000));
    console.log('Bridging WETH from Sepolia to Holesky...');
    const sepoliaWethSuccess = await bridgeWethSepoliaToHolesky(wethAmountWei);
    if (!sepoliaWethSuccess) {
    console.log('Sepolia to Holesky WETH bridge failed');
    break;
    }



  console.log(`Loop ${i + 1} completed successfully`);
const delaySeconds = 1 + Math.random() * 29; // Random number between 1 and 30
const delayMilliseconds = delaySeconds * 1000;
console.log(`Waiting for ${delaySeconds.toFixed(2)} seconds before next loop...`);
await new Promise(resolve => setTimeout(resolve, delayMilliseconds));
  }
}


main().catch((error) => {
  console.error('Error:', error);
});
