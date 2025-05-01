# Smart Contract Checker

A command line tool that helps detect vulnerabilities in Solidity smart contracts using Slither and LLMs to give concrete feedback. The tool scores contracts out of 10 based on severity of the detected vulnerabilities. Also provides a detailed report in json format.

## Setup

1. Create Project Directory:

```shell
mkdir smart-contract-checker
cd smart-contract-checker
npm init -y
```


2. Install Node.js Dependencies:

```shell
npm install axios @openzeppelin/contracts
```

3. Create a python virtual environment and activate it
```shell
python3 -m venv slither-env
source slither-env/bin/activate
```

4. Install Slither:
```shell
pip3 install slither-analyzer
```
then verify with 
```shell
slither --version.
```
On Windows, use WSL2 if issues arise (see https://github.com/crytic/slither/wiki/Installation).


5. Set Up Environment:
Create a .env file in the project root to save the Grok API key:
```shell
GROK_API_KEY=[your_grok_api_key]
```

6. Install Hardhat:
```shell
npm install --save-dev hardhat
```

## Running the tool

1. Open command line and go into the project folder `cd smart-contract-checker` 
2. Run with `node index.js contracts/TestContract.sol`
3. With hardhat all contracts are stored in the contracts folder, so save them in `/contracts` so Slither can detect them.
4. Apart from the output visible on the command line, a detailed report is also saved in `principal_protection_report.json` at root level.


## Scoring
1. The tool must evaluate contracts for vulnerabilities that risk loss of principal, focusing on:
    - **Arithmetic Safety**: Use of SafeMath or Solidity ^0.8.0’s overflow checks to prevent balance manipulation.
    - **Reentrancy Protection**: Use of ReentrancyGuard or equivalent to prevent recursive call exploits.
    - **Access Control**: Secure use of Ownable, AccessControl, or similar to prevent unauthorized actions.
    - **Audited Libraries**: Use of trusted libraries (e.g., OpenZeppelin ERC20/ERC721) to minimize bugs.
    - **Safe External Calls**: Minimized and secure calls to prevent reentrancy or delegatecall exploits.
    - **ERC20/ERC721 Compliance**: Correct token standard implementation for safe transfers.
    - **Event Logging**: Proper events for transfers and approvals to ensure auditability.
    - **Solidity Version Safety**: Use of a recent, secure version (e.g., ^0.8.0) to avoid compiler bugs.

2. Finally the tool assigns a score from 0 to 10 based on contract security as follows:
    - Base Score: 10 (perfect security).
    - Deductions:
        - Critical Issues (e.g., reentrancy, missing access control): -3 points each.
        - Moderate Issues (e.g., missing event logging): -1 point each.
        - Minor Issues (e.g., older but safe Solidity version): -0.5 points each.
    - Minimum Score: 0.


