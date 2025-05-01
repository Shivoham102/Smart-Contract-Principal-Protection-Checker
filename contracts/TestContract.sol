// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract TestContract is ERC20 {
    address public owner;

    constructor() ERC20("TestToken", "TST") {
        owner = msg.sender;
        _mint(msg.sender, 1000 * 10 ** decimals());
    }

    function transferWithFee(address recipient, uint256 amount) public {
        uint256 fee = amount / 100; // 1% fee
        _transfer(msg.sender, recipient, amount - fee);
        _transfer(msg.sender, owner, fee);
    }
}