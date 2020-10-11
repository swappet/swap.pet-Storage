// contracts/pUSD.sol
// Copyright (C) 2020, 2021, 2022 Swap.Pet@pm.me
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0; 
 
import "@openzeppelin/contracts/GSN/Context.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
// import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract Storage is Context, Ownable, AccessControl{

    mapping (string => string) public keyvalue;
    bytes32 public constant GOVERNANCE = keccak256("GOVERNANCE");
    bytes32 public constant CONTROLLER = keccak256("CONTROLLER");
    bytes32 public constant ALLOWS = keccak256("ALLOWS");
    bytes32 public constant DENYS = keccak256("DENYS");

    constructor() public { 
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        _setupRole(GOVERNANCE, _msgSender());
        _setupRole(CONTROLLER, _msgSender());
        _setupRole(ALLOWS, _msgSender());
    }
    modifier onlyGovernance() {
        require(hasRole(GOVERNANCE, _msgSender()), "Storage: Not governance");
        _;
    }
    modifier onlyController() {
        require(hasRole(CONTROLLER, _msgSender()), "Storage: Not controller");
        _;
    }
    modifier onlyGovernanceOrController() {
        require(hasRole(GOVERNANCE, _msgSender()) || hasRole(CONTROLLER, _msgSender()) , "Storage: Not controller or governance");
        _;
    } 
    function renounceRole(bytes32 role, address account) public virtual override{ 
        require( !hasRole(DENYS, _msgSender()) && account == _msgSender(), "Storage: can only renounce roles for self and not in deny list");
        super._revokeRole(role, account);
    }
    function setGovernance(address account) public onlyOwner {
        require(account != address(0), "Storage: Not empty");
        _setupRole(GOVERNANCE, account); 
    }

    function setController(address account) public onlyGovernance {
        require(account != address(0), "Storage: Not empty");
        _setupRole(CONTROLLER, account); 
    }

    function addKey(string key, string value) public onlyGovernance{
        require(bytes(keyvalue[key]).length == 0);
        keyvalue[key] = value;
    }
    function delKey(string key) public returns (string) onlyGovernance{ 
        require(bytes(keyvalue[key]).length != 0);
        string prev = keyvalue[key];
        delete keyvalue[key];
        return prev;
    }
    function setKey(string key, string newValue) public onlyGovernance{ 
        require(bytes(keyvalue[key]).length != 0);
        keyvalue[key] = newValue;
    } 

    function addAllow(address account) public onlyGovernanceOrController {
        require(account != address(0), "Storage: Not empty");
        _setupRole(ALLOWS, account); 
    } 
    function removeAllow(address account) public onlyGovernanceOrController {
        require(account != address(0), "Storage: Not empty");
        _revokeRole(ALLOWS, account); 
    } 
    function addDeny(address account) public onlyGovernanceOrController {
        require(account != address(0), "Storage: Not empty");
        _setupRole(DENYS, account); 
    } 
    function removeDeny(address account) public onlyGovernanceOrController {
        require(account != address(0), "Storage: Not empty");
        _revokeRole(DENYS, account); 
    } 
}

