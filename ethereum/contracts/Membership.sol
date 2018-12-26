pragma solidity 0.5.2;

contract Membership {

    uint256 constant UINT_48_MASK = 0xffffffffffff;
    uint256 constant UINT_32_MASK = 0xffffffff;

    struct Member {
        uint256 packed;
    }

    mapping (address => Member) public members;
    address[] public memberList;

    address public admin;

    event SetMember(address votingAddr, uint48 weight, uint48 startTime, uint48 endTime);


    modifier onlyAdmin() {
        require(msg.sender == admin, "msg.sender not admin");
        _;
    }



    constructor() public {
        admin = msg.sender;
    }

    function setMember(address votingAddr, uint32 weight, uint48 startTime, uint48 endTime) external onlyAdmin {
        if (members[votingAddr].packed == 0) {
            memberList.push(votingAddr);
        }
        members[votingAddr] = Member(pack(weight, startTime, endTime));
        emit SetMember(votingAddr, weight, startTime, endTime);
    }

    function getMember(address voter) external view returns (uint32 weight, uint48 startTime, uint48 endTime) {
        (weight, startTime, endTime) = unpack(members[voter].packed);
    }

    function pack(uint32 weight, uint48 start, uint48 end) internal pure returns (uint256) {
        return (uint256(weight) << 96) | (uint256(start) << 48) | uint256(end);
    }

    function unpack(uint256 packed) internal pure returns (uint32 weight, uint48 start, uint48 end) {
        weight = uint32((packed >> 96) & UINT_32_MASK);
        start = uint48((packed >> 48) & UINT_48_MASK);
        end = uint48(packed & UINT_48_MASK);
    }


    function balanceOf(address v) external view returns (uint256) {
        uint32 weight; uint48 start; uint48 end;
        (weight, start, end) = unpack(members[v].packed);
        if (start <= now && end >= now) {
            return weight;
        }
        return 0;
    }

}
