## Module Template

**A Base contract for building ERC-7579 IValidator modules that support ERC-7739**

## Motivation
[ERC-7739](https://ethereum-magicians.org/t/erc-7739-readable-typed-signatures-for-smart-accounts/20513) brings improved security and transparency to verifying ERC-1271 signatures.  
However, it can be difficult to implement in a modular eco-system.  
This repo introduces base contract for [ERC-7579 IValidator](https://eips.ethereum.org/EIPS/eip-7579#validators) modules that want to utilize ERC-7739.

## What's Included
- `ERC7739Validator.sol`. This is the base contract one can inherit to introduce ERC-7739 support in a validator module.
- `SampleK1ValidatorWithERC7739.sol`. Sample validator module built using `ERC7739Validator` base. Use this as an example on how to build validator modules. NB: this module is also an [`ISessionValidator`](https://github.com/erc7579/smartsessions/wiki/Smart-Sessions#isessionvalidator) for Smart Sessions module.
- `EIP5267CompatibilityFallback.sol`. An [ERC-7579 Fallback Module](https://eips.ethereum.org/EIPS/eip-7579#fallback-handlers) that adds support of EIP-5267 `eip712Domain()` interface to a smart account. This interface is required by ERC-7739 flow. So the Smart Account should expose it directly or via the fallback.
- Libs in the `utils` folder are not used by `ERC7739Validator`. They are used by `SampleK1ValidatorWithERC7739` and `EIP5267CompatibilityFallback, so they may be optional for one's usecase.

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
NB: it keeps anvil running in the background. So for the next tests you may use `forge test` as usual.  
Do not forget to use `lsof -t -i tcp:8545 | xargs kill` to kill Anvil.  
Or you can always just manually run Anvil in a separate terminal and ingore `pnpm test:anvil` script.  

You can rm this test if you're going to clone this repo and build a new validator in it.  
Then you won't need to spin up anvil every time and you can just use `forge test`.  

### Developing
Just inherit `ERC7739Validator` in your validator module and you're all set up.  
Smart Accounts that do not expose EIP-5267 `eip712Domain()` method must install `EIP5267CompatibilityFallback` in order to benefit from ERC-7739's improved security.  

This repo is based on [Rhinestone Module Template](https://github.com/rhinestonewtf/module-template).  
Please visit the link above if you need more instructions on how to build, test and deploy a module.
## Contributing

For feature or change requests, feel free to open a PR, start a discussion or get in touch with us.
