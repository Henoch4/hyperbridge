# Remove superApprove from HyperFungibleTokenImpl

Removes permissionless `superApprove(owner, spender)` from `evm/src/utils/HyperFungibleTokenImpl.sol`. It called `_approve` with no `msg.sender` check, allowing anyone to set unlimited allowance for any holder and drain via `transferFrom`.

Test-only helper retained on `evm/tests/foundry/FeeToken.sol` (extends Impl). Production token has no arbitrary approval path. `MockUSDC` test mock unchanged.
