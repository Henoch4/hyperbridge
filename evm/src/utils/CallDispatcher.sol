// Copyright (C) Polytope Labs Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
pragma solidity ^0.8.17;

import {ICallDispatcher, Call} from "@hyperbridge/core/interfaces/ICallDispatcher.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title The CallDispatcher
 * @author Polytope Labs (hello@polytope.technology)
 *
 * @notice This contract is used to dispatch calls to other contracts.
 *
 * @dev Holds user funds transiently while an app's order flow runs, so `dispatch` is restricted
 * to owner-authorized callers: the apps that fund it. Anyone else calling it could spend those
 * balances through arbitrary calldata. The owner authorizes each consumer (e.g. the gateway)
 * with `setAuthorized` at deploy time.
 */
contract CallDispatcher is ICallDispatcher, Ownable {
    /**
     * @dev error thrown when the target is not a contract.
     */
    error NotContract(address target);

    /**
     * @dev error thrown when a call fails.
     */
    error CallFailed(address target, bytes result);

    /**
     * @dev error thrown when the caller is not authorized to dispatch.
     */
    error NotAuthorized(address caller);

    /**
     * @dev Emitted when a dispatcher's authorization is set.
     */
    event AuthorizedUpdated(address indexed account, bool authorized);

    /**
     * @dev The apps allowed to call `dispatch`.
     */
    mapping(address => bool) public isAuthorized;

    /**
     * @dev Records the owner, who authorizes dispatchers.
     */
    constructor(address owner_) Ownable(owner_) {}

    /**
     * @dev Authorizes or deauthorizes a dispatch caller. Only the owner.
     */
    function setAuthorized(address account, bool authorized) external onlyOwner {
        isAuthorized[account] = authorized;
        emit AuthorizedUpdated(account, authorized);
    }

    /**
     * @dev Reverts unless the caller was authorized with `setAuthorized`.
     */
    modifier onlyAuthorized() {
        if (!isAuthorized[msg.sender]) revert NotAuthorized(msg.sender);
        _;
    }

    /**
     * @dev Receive function to accept ETH transfers
     */
    receive() external payable {}

    /**
     *  @dev reverts if the caller is not authorized, the target is not a contract or if any of the calls reverts.
     */
    function dispatch(bytes memory encoded) external onlyAuthorized {
        Call[] memory calls = abi.decode(encoded, (Call[]));
        uint256 callsLen = calls.length;
        for (uint256 i = 0; i < callsLen; ++i) {
            Call memory call = calls[i];
            uint32 size;
            address to = call.to;
            assembly {
                size := extcodesize(to)
            }

            if (size == 0) {
                revert NotContract(to);
            }

            (bool success, bytes memory result) = to.call{value: call.value}(call.data);
            if (!success) revert CallFailed(to, result);
        }
    }
}
