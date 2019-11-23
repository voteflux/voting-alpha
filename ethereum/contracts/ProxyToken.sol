pragma solidity ^0.4.25;

import "../node_modules/openzeppelin-solidity/contracts/access/Roles.sol";

interface IERC20 {
    function balanceOf(address _who) external view returns (uint256);
}

contract proxyToken {
    using SafeMath for uint256;
    using Roles for Roles.Role;

    uint8 public tokenCount = 0;
    mapping( uint256 => address)  public tokens;
    mapping(address => uint256)  public tokenIndex;


    Roles.Role private admins;
    event AddAdmin(address admin);
    event RevokeAdmin(address oldAdmin);
    event AddToken(address token);
    event RemoveToken(address oldToken);


    modifier onlyAdmin() {
        require(admins.has(msg.sender), "NOT_ADMIN");
        _;
    }

    constructor() public {
        admins.add(msg.sender);
        emit AddAdmin(msg.sender);
    }

    // manage roles
    function addAdmin(address _a) external onlyAdmin {
        admins.add(_a);
        emit AddAdmin(msg.sender);
    }
    function revokeAdminSelf() external onlyAdmin {
        admins.remove(msg.sender);
        emit RevokeAdmin(msg.sender);
    }
    function isAdmin(address a) external view returns (bool) {
        return admins.has(a);
    }
    
    // get balances
    function balanceOf (address _owner) public view returns (uint256 balance) {
        for (uint256 i = 0; i < tokenCount; i++) {
            balance = balance.add(balanceOfByToken(_owner,tokens[i]));
        }
        return balance;
    }

    function balanceOfByToken(address _owner, address _token) public view returns (uint256 balance) {
        return IERC20(_token).balanceOf(_owner);
    }

    function addToken (address _token) public onlyAdmin returns (bool) {
        require(_token != address(0x0) && tokenIndex[_token] == 0 && tokens[0] !=_token);
        tokenIndex[_token] = tokenCount;
        tokens[tokenCount] = _token;
        tokenCount = tokenCount + 1;
        emit AddToken(_token);
        return true;
    }

    function removeToken (address _token) public onlyAdmin returns (bool) {
        require(_token != address(0) );
        tokenCount = tokenCount - 1;
        tokenIndex[tokens[tokenCount]] = tokenIndex[_token];
        tokens[tokenIndex[_token]] = tokens[tokenCount];
        
        tokens[tokenCount] = address(0x0);
        tokenIndex[_token] = 0;
        emit RemoveToken(_token);
        return true;
    }
}


library SafeMath {
  function add(uint256 a, uint256 b) internal pure returns (uint256 c) {
      c = a + b;
      require(c >= a);
  }
  function sub(uint256 a, uint256 b) internal pure returns (uint256 c) {
      require(b <= a);
      c = a - b;
  }
  function mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
      c = a * b;
      require(a == 0 || c / a == b);
  }
  function div(uint256 a, uint256 b) internal pure returns (uint256 c) {
      require(b > 0);
      c = a / b;
  }
  function mod(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b != 0);
    return a % b;
  }
}