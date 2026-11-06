// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Equipment {
    address public owner;

    struct EquipmentItem {
        uint256 id;
        string name;
        string status;
    }

    mapping(uint256 => EquipmentItem) private equipment;
    uint256[] private equipmentIds;

    event EquipmentCreated(uint256 id, string name);
    event EquipmentStatusChanged(uint256 id, string status);

    modifier onlyOwner() {
        require(msg.sender == owner, "Access denied");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function createEquipment(
        uint256 id,
        string memory name
    ) public onlyOwner {
        require(equipment[id].id == 0, "Already exists");

        equipment[id] = EquipmentItem(id, name, "Active");
        equipmentIds.push(id);

        emit EquipmentCreated(id, name);
    }

    function getEquipment(
        uint256 id
    ) public view returns (
        uint256,
        string memory,
        string memory
    ) {
        require(equipment[id].id != 0, "Not found");

        EquipmentItem memory item = equipment[id];

        return (item.id, item.name, item.status);
    }

    function getAllEquipment()
        public view returns (EquipmentItem[] memory)
    {
        EquipmentItem[] memory result =
            new EquipmentItem[](equipmentIds.length);

        for (uint256 i = 0; i < equipmentIds.length; i++) {
            result[i] = equipment[equipmentIds[i]];
        }

        return result;
    }

    function updateEquipmentStatus(
        uint256 id,
        string memory newStatus
    ) public onlyOwner {
        require(equipment[id].id != 0, "Not found");

        equipment[id].status = newStatus;

        emit EquipmentStatusChanged(id, newStatus);
    }
}