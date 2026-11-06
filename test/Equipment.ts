
import { expect } from "chai";
import { network } from "hardhat";

describe("Equipment Integration Tests", function () {
  async function deployEquipment() {
    const { ethers } = await network.connect();
    const [owner, user] = await ethers.getSigners();

    const factory = await ethers.getContractFactory("Equipment");
    const equipment = await factory.deploy();
    await equipment.waitForDeployment();

    return { equipment, owner, user };
  }

  it("1. Создание оборудования", async function () {
    const { equipment } = await deployEquipment();

    await expect(equipment.createEquipment(1, "P-01"))
      .to.emit(equipment, "EquipmentCreated")
      .withArgs(1, "P-01");

    const item = await equipment.getEquipment(1);
    expect(item[1]).to.equal("P-01");
    expect(item[2]).to.equal("Active");
  });

  it("2. Чтение оборудования", async function () {
    const { equipment } = await deployEquipment();

    await equipment.createEquipment(2, "P-02");

    const item = await equipment.getEquipment(2);
    expect(item[0]).to.equal(2n);
    expect(item[1]).to.equal("P-02");
    expect(item[2]).to.equal("Active");
  });

  it("3. Получение всего списка", async function () {
    const { equipment } = await deployEquipment();

    await equipment.createEquipment(1, "P-01");
    await equipment.createEquipment(2, "P-02");

    const items = await equipment.getAllEquipment();

    expect(items.length).to.equal(2);
    expect(items[0].name).to.equal("P-01");
    expect(items[1].name).to.equal("P-02");
  });

  it("4. Изменение статуса", async function () {
    const { equipment } = await deployEquipment();

    await equipment.createEquipment(3, "P-03");

    await expect(
      equipment.updateEquipmentStatus(3, "Maintenance")
    )
      .to.emit(equipment, "EquipmentStatusChanged")
      .withArgs(3, "Maintenance");

    const item = await equipment.getEquipment(3);
    expect(item[2]).to.equal("Maintenance");
  });

  it("5. Запрет повторного создания ID", async function () {
    const { equipment } = await deployEquipment();

    await equipment.createEquipment(4, "P-04");

    await expect(
      equipment.createEquipment(4, "P-04-duplicate")
    ).to.be.revertedWith("Already exists");
  });

  it("6. Отказ при чтении несуществующего оборудования", async function () {
    const { equipment } = await deployEquipment();

    await expect(
      equipment.getEquipment(999)
    ).to.be.revertedWith("Not found");
  });

  it("7. Запрет изменения данных посторонним пользователем", async function () {
    const { equipment, user } = await deployEquipment();

    await equipment.createEquipment(5, "P-05");

    const unauthorized = equipment.connect(user);

    await expect(
      unauthorized.updateEquipmentStatus(5, "Inactive")
    ).to.be.revertedWith("Access denied");
  });

  it("8. Проверка целостности ID и названия", async function () {
    const { equipment } = await deployEquipment();

    await equipment.createEquipment(6, "P-06");
    await equipment.updateEquipmentStatus(6, "Maintenance");

    const item = await equipment.getEquipment(6);

    expect(item[0]).to.equal(6n);
    expect(item[1]).to.equal("P-06");
    expect(item[2]).to.equal("Maintenance");
  });

  it("9. Инвариант: разные ID сохраняют разные объекты", async function () {
    const { equipment } = await deployEquipment();

    for (let i = 1; i <= 20; i++) {
      await equipment.createEquipment(i, `Equipment-${i}`);
    }

    const items = await equipment.getAllEquipment();

    expect(items.length).to.equal(20);

    for (let i = 0; i < 20; i++) {
      expect(items[i].id).to.equal(BigInt(i + 1));
      expect(items[i].name).to.equal(`Equipment-${i + 1}`);
    }
  });

  it("10. Проверка свойства последовательных изменений статуса", async function () {
    const { equipment } = await deployEquipment();

    await equipment.createEquipment(100, "Fuzz-Test");

    const statuses = [
      "Maintenance",
      "Inactive",
      "Active",
      "Maintenance",
      "Inactive"
    ];

    for (const status of statuses) {
      await equipment.updateEquipmentStatus(100, status);
    }

    const item = await equipment.getEquipment(100);

    expect(item[2]).to.equal(statuses[statuses.length - 1]);
  });
});
