const { ethers } = require('ethers');  
require('dotenv').config();  
const fs = require('fs');
  
// Contract addresses  
const WALLET_CORE_ADDRESS = '0x80296FF8D1ED46f8e3C7992664D13B833504c2Bb'; // Sepolia address  
const ERC20_TOKEN_ADDRESS = '0xef866858fedd64d20b6cb4359b09321e9301ef5d';  
const NFT_CONTRACT_ADDRESS = 'YOUR_NFT_CONTRACT_ADDRESS';  
const RECIPIENT_ADDRESS = '0x9B1Ca7b65219791896F8432032AeA1A93ab7C3C2';  
  
// ABIs  
const walletCoreAbi = [  
  'function executeFromExecutor(tuple(address target, uint256 value, bytes data)[] calls, tuple(uint256 id, address executor, address validator, uint256 validUntil, uint256 validAfter, bytes preHook, bytes postHook, bytes signature) session) external',  
  'function getSessionTypedHash(tuple(uint256 id, address executor, address validator, uint256 validUntil, uint256 validAfter, bytes preHook, bytes postHook, bytes signature) session) external view returns (bytes32)'  
];  
  
const erc20Abi = [  
  'function transfer(address to, uint256 amount) external returns (bool)'  
];  
  
const nftAbi = [  
  'function transferFrom(address from, address to, uint256 tokenId) external'  
];  
  
const CREATE_AND_SIGN_SESSION = false;

async function main() {  
  console.log('Starting wallet upgrade and session-based execution demo...');  
    
  // Connect to Sepolia  
  const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);  
    
  // Set up wallets  
  const userWallet = new ethers.Wallet(process.env.USER_PRIVATE_KEY, provider);  
  const executorWallet = new ethers.Wallet(process.env.EXECUTOR_PRIVATE_KEY, provider);  
    
  console.log(`User wallet address: ${userWallet.address}`);  
  console.log(`Executor wallet address: ${executorWallet.address}`);  
    
  // Step 1: Upgrade wallet with EIP-7702 Type-4 transaction  
  // await upgradeWalletWithEIP7702(userWallet, provider);  
    
  // Step 2: Create and sign sessions for different contract interactions  
  console.log('\n--- STEP 2: Creating and Signing Sessions ---');  
    
  // Create contract instances  
  const walletCore = new ethers.Contract(WALLET_CORE_ADDRESS, walletCoreAbi, provider);
  const userSmartWallet = new ethers.Contract(userWallet.address, walletCoreAbi, provider);

  let session;
  if (CREATE_AND_SIGN_SESSION) {
    session = await createAndSignSession(userSmartWallet, executorWallet, provider);
    console.log('Session created and signed');
    console.log(session);
    fs.writeFileSync('session.json', JSON.stringify(session, null, 2));
  } else {
    session = JSON.parse(fs.readFileSync('session.json', 'utf-8'));
    console.log('Session loaded from disk');
    console.log(session);
  }
    
  // Example 1: ERC20 Token Transfer  
  const erc20TransferCall = createERC20TransferCall(ERC20_TOKEN_ADDRESS, RECIPIENT_ADDRESS, '0.1');
    
  // Example 2: ETH Transfer  
  //const ethTransferCall = createETHTransferCall(RECIPIENT_ADDRESS, '0.01');  
    
  // Example 3: NFT Transfer  
  //const nftTransferCall = createNFTTransferCall(NFT_CONTRACT_ADDRESS, userWallet.address, RECIPIENT_ADDRESS, 1);  
    
  // Step 3: Execute the sessions  
  console.log('\n--- STEP 3: Executing Sessions ---');  
    
  // Execute each session (in a real scenario, only one would be executed)  
  await executeSession(executorWallet, userWallet, walletCore, [erc20TransferCall], session, provider);  
  // Uncomment to execute other sessions  
  // await executeSession(executorWallet, walletCore, [ethTransferCall], session);  
  // await executeSession(executorWallet, walletCore, [nftTransferCall], session);  
}  
  
async function upgradeWalletWithEIP7702(wallet, provider) {  
  // [Existing implementation remains unchanged]  
  console.log('\n--- STEP 1: Upgrading wallet with EIP-7702 Type-4 transaction ---');  
    
  // Get WalletCore interface  
  const walletCoreAbi = [  
    'function initialize() external'  
  ];  
  const walletCore = new ethers.Contract(WALLET_CORE_ADDRESS, walletCoreAbi, provider);  
    
  // Encode initialize function call  
  const calldata = walletCore.interface.encodeFunctionData('initialize');  
    
  // Get current chain ID and nonce  
  const chainId = (await provider.getNetwork()).chainId;  
  const currentNonce = await provider.getTransactionCount(wallet.address);  
    
  console.log(`Chain ID: ${chainId}`);  
  console.log(`Current nonce: ${currentNonce}`);  
    
  // Create authorization data  
  const authorizationData = {  
    chainId: ethers.toBeHex(chainId),  
    address: WALLET_CORE_ADDRESS,  
    nonce: ethers.toBeHex(currentNonce + 1),  
  };  
    
  // Encode authorization data  
  const encodedAuthorizationData = ethers.concat([  
    '0x05', // MAGIC code for EIP7702  
    ethers.encodeRlp([  
      authorizationData.chainId,  
      authorizationData.address,  
      authorizationData.nonce,  
    ])  
  ]);  
    
  // Sign authorization data  
  const authorizationDataHash = ethers.keccak256(encodedAuthorizationData);  
  const authorizationSignature = wallet.signingKey.sign(authorizationDataHash);  
    
  // Add signature components to authorization data  
  authorizationData.yParity = authorizationSignature.yParity === 0 ? '0x' : '0x01';  
  authorizationData.r = authorizationSignature.r;  
  authorizationData.s = authorizationSignature.s;  
    
  // Get fee data  
  const feeData = await provider.getFeeData();  
    
  // Prepare transaction data  
  const txData = [  
    authorizationData.chainId,  
    currentNonce === 0 ? "0x" : ethers.toBeHex(currentNonce),  
    ethers.toBeHex(feeData.maxPriorityFeePerGas),  
    ethers.toBeHex(feeData.maxFeePerGas),  
    ethers.toBeHex(1000000), // Gas limit  
    wallet.address, // Sender address  
    '0x', // No ETH value  
    calldata, // initialize() function call  
    [], // Empty access list  
    [  
      [  
        authorizationData.chainId,  
        authorizationData.address,  
        authorizationData.nonce,  
        authorizationData.yParity,  
        authorizationData.r,  
        authorizationData.s  
      ]  
    ]  
  ];  
    
  // Encode transaction with type prefix  
  const encodedTxData = ethers.concat([  
    '0x04', // Transaction type identifier for EIP-7702  
    ethers.encodeRlp(txData)  
  ]);  
    
  // Sign the transaction  
  const txDataHash = ethers.keccak256(encodedTxData);  
  const txSignature = wallet.signingKey.sign(txDataHash);  
    
  // Construct the signed transaction  
  const signedTx = ethers.hexlify(ethers.concat([  
    '0x04',  
    ethers.encodeRlp([  
      ...txData,  
      txSignature.yParity === 0 ? '0x' : '0x01',  
      txSignature.r,  
      txSignature.s  
    ])  
  ]));  
    
  // Send the transaction  
  console.log('Sending EIP-7702 Type-4 transaction...');  
  const tx = await provider.send('eth_sendRawTransaction', [signedTx]);  
  console.log(`Transaction sent: ${tx}`);  
    
  // Wait for transaction to be mined  
  console.log('Waiting for transaction to be mined...');  
  await provider.waitForTransaction(tx);  
  console.log('Wallet upgrade complete!');  
}  
  
// FUNCTION 1: Create and sign a session (user side)  
async function createAndSignSession(userSmartWallet, executorWallet, provider) {
  const now = Math.floor(Date.now() / 1000);  
  const session = {  
    id: Math.floor(Math.random() * 1000000), // Random session ID for demo  
    executor: executorWallet.address, // Executor address  
    validator: '0x0000000000000000000000000000000000000001', // SELF_VALIDATION_ADDRESS defined in https://github.com/okx/wallet-core/blob/9532ac6602bedd6f3bc4fa5e491153bfa70cd7c0/src/lib/WalletCoreLib.sol#L21
    validUntil: now + 3600, // Valid for 1 hour  
    validAfter: now - 300,
    preHook: '0x', // No pre-hook  
    postHook: '0x', // No post-hook  
    signature: '0x' // Will be filled after signing  
  };  
    
  console.log('Session parameters:');  
  console.log({  
    id: session.id,  
    executor: session.executor,  
    validator: session.validator,  
    validUntil: new Date(session.validUntil * 1000).toISOString(),  
    validAfter: new Date(session.validAfter * 1000).toISOString()  
  });

  // NOTE: The following is calculating EIP-712 hash of the session, which is the same as the view function getSessionTypedHash() in solidity

  // const SESSION_TYPEHASH = ethers.keccak256(
  //   ethers.toUtf8Bytes("Session(address wallet,uint256 id,address executor,address validator,uint256 validUntil,uint256 validAfter,bytes preHook,bytes postHook)")
  // );

  // // Equivalent to _getSessionHash()
  // const sessionHash = ethers.keccak256(
  //   ethers.AbiCoder.defaultAbiCoder().encode(
  //     ['bytes32', 'address', 'uint256', 'address', 'address', 'uint256', 'uint256', 'bytes32', 'bytes32'],
  //     [
  //       SESSION_TYPEHASH,
  //       WALLET_CORE_ADDRESS, // _walletImplementation() in solidity
  //       session.id,
  //       session.executor,
  //       session.validator,
  //       session.validUntil,
  //       session.validAfter,
  //       ethers.keccak256(session.preHook),
  //       ethers.keccak256(session.postHook)
  //     ]
  //   )
  // );

  // // Equivalent to _hashTypedDataV4()
  // const DOMAIN_SEPARATOR = ethers.keccak256(
  //   ethers.AbiCoder.defaultAbiCoder().encode(
  //     ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
  //     [
  //       ethers.keccak256(ethers.toUtf8Bytes('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')),
  //       ethers.keccak256(ethers.toUtf8Bytes('wallet-core')),
  //       ethers.keccak256(ethers.toUtf8Bytes('1.0.0')),
  //       await provider.getNetwork().then(n => n.chainId),
  //       userSmartWallet.target
  //     ]
  //   )
  // );

  // const finalHash = ethers.keccak256(
  //   ethers.concat([
  //     '0x1901', // EIP-191 prefix + EIP-712 version byte
  //     DOMAIN_SEPARATOR,
  //     sessionHash // This is the _getSessionHash result
  //   ])
  // );

  const sessionHashFromContract = await userSmartWallet.getSessionTypedHash(session);
  // console.log('EIP-712 Typed Hash from contract (getSessionTypedHash):', sessionHashFromContract);
  // console.log('EIP-712 Typed Hash from local JS (finalHash):', finalHash);

  // if (finalHash === sessionHashFromContract) {
  //   console.log('SUCCESS: Local EIP-712 hash matches contract EIP-712 hash!');
  // } else {
  //   console.log('ERROR: Local EIP-712 hash does NOT match contract EIP-712 hash.');
  // }
  
  // Raw ECDSA sign
  const signingKey = new ethers.SigningKey("0x" + process.env.USER_PRIVATE_KEY);
  const signatureObj = signingKey.sign(sessionHashFromContract);
  
  // Pack r,s,v like Solidity
  session.signature = ethers.concat([
    signatureObj.r,
    signatureObj.s,
    ethers.toBeHex(signatureObj.v)
  ]);
    
  console.log('Session signed by user', session.signature);
    
  // Return the signed session  
  return session;  
}  
  
// FUNCTION 2: Execute a session (executor side)  
async function executeSession(executorWallet, userWallet, walletCore, calls, session, provider) {  
  console.log(`Executing session ${session.id} with ${calls.length} calls...`);  
    
  try {
    console.log('Sending transaction to blockchain...');  
    
    const userSmartWallet = new ethers.Contract(userWallet.address, walletCoreAbi, provider);

    const tx = await userSmartWallet.connect(executorWallet).executeFromExecutor(calls, session, {
      gasLimit: 500000, // Fixed high gas limit
    });  
      
    console.log(`Transaction sent: ${tx.hash}`);  
    const receipt = await tx.wait();
    console.log('\nTransaction receipt:');
    console.log('Status:', receipt.status);
    console.log('Gas used:', receipt.gasUsed.toString());
    console.log('Logs:', receipt.logs);
    
    return tx;
  } catch (error) {
    console.error('Detailed error info:');
    console.error('Error code:', error.code);
    console.error('Error name:', error.name);
    console.error('Error message:', error.message);
    if (error.transaction) {
      console.error('\nTransaction details:');
      console.error('From:', error.transaction.from);
      console.error('To:', error.transaction.to);
      console.error('Data:', error.transaction.data);
    }
    if (error.error) {
      console.error('\nUnderlying error:');
      console.error('Code:', error.error.code);
      console.error('Message:', error.error.message);
    }
    throw error;
  }
}  
  
// Helper functions for creating different types of calls  
  
// 1. ERC20 Token Transfer  
function createERC20TransferCall(tokenAddress, recipient, amount) {  
  console.log(`Creating ERC20 transfer call: ${amount} tokens to ${recipient}`);  
    
  const erc20Interface = new ethers.Interface(erc20Abi);  
  const transferCalldata = erc20Interface.encodeFunctionData('transfer', [  
    recipient,  
    ethers.parseUnits(amount, 18) // Assuming 18 decimals  
  ]);  
    
  return {  
    target: tokenAddress,  
    value: 0, // No ETH value  
    data: transferCalldata  
  };  
}  
  
// 2. ETH Transfer  
function createETHTransferCall(recipient, amount) {  
  console.log(`Creating ETH transfer call: ${amount} ETH to ${recipient}`);  
    
  return {  
    target: recipient,  
    value: ethers.parseEther(amount),  
    data: '0x' // Empty calldata for simple ETH transfer  
  };  
}  
  
// 3. NFT Transfer  
function createNFTTransferCall(nftAddress, from, to, tokenId) {  
  console.log(`Creating NFT transfer call: Token ID ${tokenId} from ${from} to ${to}`);  
    
  const nftInterface = new ethers.Interface(nftAbi);  
  const transferCalldata = nftInterface.encodeFunctionData('transferFrom', [  
    from,  
    to,  
    tokenId  
  ]);  
    
  return {  
    target: nftAddress,  
    value: 0, // No ETH value  
    data: transferCalldata  
  };  
}  
  
main()  
  .then(() => process.exit(0))  
  .catch((error) => {  
    console.error('Error:', error);  
    process.exit(1);  
  });