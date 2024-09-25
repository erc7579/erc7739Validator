## Module Template

**A Base contract for building ERC-7579 validator modules that support ERC-7739**

## Motivation
[ERC-7739](https://ethereum-magicians.org/t/erc-7739-readable-typed-signatures-for-smart-accounts/20513) brings improved security and transparency to verifying ERC-1271 signatures.
However, it can be difficult to implement in a modular eco-system.
This repo introduces base contract for ERC-7579 validator modules that want to utilize ERC-7739.



## What's Included

## Usage
### Install

```shell
pnpm install
```

### Test

One of the tests `SampleERC7739ValidatorTest_RPC.t.sol` uses `anvil` local node to mimic the RPC call.
```shell
pnpm test:anvil
```
This task runs `anvil` first, then `forge test` in parallel.

You can rm this test if you're going to clone this repo and build a new validator in it.
Then you won't need to spin up anvil every time and you can just use `forge test`.

### Developing
Just inherit `ERC7739Validator` in your validator module and you're all set up.
Smart Accounts that do not expose EIP-5267 `eip712Domain()` method must install `EIP5267CompatibilityFallback` in order to benefit from ERC-7739's improved security.

This repo is based on [Rhinestone Module Template](https://github.com/rhinestonewtf/module-template).
Please visit the link above if you need more instructions on how to build, test and deplpoy a module.

## Contributing

For feature or change requests, feel free to open a PR, start a discussion or get in touch with us.
