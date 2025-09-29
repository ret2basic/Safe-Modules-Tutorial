// Import necessary libraries and types
import { ethers } from "hardhat";
import { expect } from "chai";
import { Signer, TypedDataDomain, ZeroAddress } from "ethers";
import {
  Safe,
  TestToken,
  TokenWithdrawModule,
} from "../typechain-types";
import { execTransaction } from "./utils/utils";

describe("TokenWithdrawModule Tests", function () {
  // Define variables
  let deployer: Signer;
  let alice: Signer;
  let bob: Signer;
  let charlie: Signer;
  let masterCopy: any;
  let token: TestToken;
  let safe: Safe;
  let safeAddress: string;
  let chainId: bigint;

  // Setup signers and deploy contracts before running tests
  before(async () => {
    [deployer, alice, bob, charlie] = await ethers.getSigners();

    chainId = (await ethers.provider.getNetwork()).chainId;
    const safeFactory = await ethers.getContractFactory("Safe", deployer);
    masterCopy = await safeFactory.deploy();

    // Deploy a new token contract
    token = await (
      await ethers.getContractFactory("TestToken", deployer)
    ).deploy("test", "T");

    // Deploy a new SafeProxyFactory contract
    const proxyFactory = await (
      await ethers.getContractFactory("SafeProxyFactory", deployer)
    ).deploy();

    // Setup the Safe, Step 1, generate transaction data
    const safeData = masterCopy.interface.encodeFunctionData("setup", [
      [await alice.getAddress()],
      1,
      ZeroAddress,
      "0x",
      ZeroAddress,
      ZeroAddress,
      0,
      ZeroAddress,
    ]);

    // Read the safe address by executing the static call to createProxyWithNonce function
    safeAddress = await proxyFactory.createProxyWithNonce.staticCall(
      await masterCopy.getAddress(),
      safeData,
      0n
    );

    if (safeAddress === ZeroAddress) {
      throw new Error("Safe address not found");
    }

    // Setup the Safe, Step 2, execute the transaction
    await proxyFactory.createProxyWithNonce(
      await masterCopy.getAddress(),
      safeData,
      0n
    );

    safe = await ethers.getContractAt("Safe", safeAddress);

    // Mint tokens to the safe address
    await token
      .connect(deployer)
      .mint(safeAddress, BigInt(10) ** BigInt(18) * BigInt(100000));
  });

  // A Safe Module is a smart contract that is allowed to execute transactions on behalf of a Safe Smart Account.
  // This function deploys the TokenWithdrawModule contract and enables it in the Safe.
  const enableModule = async (): Promise<{
    tokenWithdrawModule: TokenWithdrawModule;
  }> => {
    // Deploy the TokenWithdrawModule contract and pass the token and safe address as arguments
    const tokenWithdrawModule = await (
      await ethers.getContractFactory("TokenWithdrawModule", deployer)
    ).deploy(token.target, safeAddress);

    // Enable the module in the safe, Step 1, generate transaction data
    const enableModuleData = masterCopy.interface.encodeFunctionData(
      "enableModule",
      [tokenWithdrawModule.target]
    );

    // Enable the module in the safe, Step 2, execute the transaction
    await execTransaction([alice], safe, safe.target, 0, enableModuleData, 0);

    // Verify that the module is enabled
    expect(await safe.isModuleEnabled.staticCall(tokenWithdrawModule.target)).to
      .be.true;

    return { tokenWithdrawModule };
  };

  // Test case to verify token transfer to bob
  it("Should successfully transfer tokens to bob", async function () {
    // Enable the module in the Safe
    const { tokenWithdrawModule } = await enableModule();

    const amount = 10000000000000000000n; // 10 * 10^18
    const deadline = 100000000000000n;
    const nonce = await tokenWithdrawModule.nonces(await bob.getAddress());

    // Our module expects a EIP-712 typed signature, so we need to define the EIP-712 domain, ...
    const domain: TypedDataDomain = {
      name: "TokenWithdrawModule",
      version: "1",
      chainId: chainId,
      verifyingContract: await tokenWithdrawModule.getAddress(),
    };

    // ... and EIP-712 types ...
    const types = {
      TokenWithdrawModule: [
        { name: "amount", type: "uint256" },
        { name: "beneficiary", type: "address" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint256" },
      ],
    };

    // ... and EIP-712 values ...
    const value = {
      amount: amount,
      beneficiary: await bob.getAddress(),
      nonce: nonce,
      deadline: deadline,
    };

    // ... and finally hash the data using EIP-712
    const digest = ethers.TypedDataEncoder.hash(domain, types, value);
    const bytesDataHash = ethers.getBytes(digest);
    let signatureBytes = "0x";

    // Alice signs the digest
    const flatSig = (await alice.signMessage(bytesDataHash))
      .replace(/1b$/, "1f")
      .replace(/1c$/, "20");
    signatureBytes += flatSig.slice(2);

    // We want to make sure that an invalid signer cannot call the module even with a valid signature
    // We test this before the valid transaction, because it would fail because of an invalid nonce otherwise
    await expect(
      tokenWithdrawModule
        .connect(charlie)
        .tokenTransfer(
          amount,
          await charlie.getAddress(),
          deadline,
          signatureBytes
        )
    ).to.be.revertedWith("GS026");

    // Now we use the signature to transfer via our module
    await tokenWithdrawModule
      .connect(bob)
      .tokenTransfer(amount, await bob.getAddress(), deadline, signatureBytes);

    // Verify the token balance of bob (should be 10000000000000000000)
    const balanceBob = await token.balanceOf.staticCall(await bob.getAddress());
    expect(balanceBob).to.be.equal(amount);

    // All done.
  });
});
