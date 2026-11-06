import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("EquipmentModule", (m) => {
  const equipment = m.contract("Equipment");

  return { equipment };
});
