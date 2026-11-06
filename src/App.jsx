
import React, { useState, useEffect, useRef } from "react";
import { ethers } from "ethers";

// ======================================================
// CONFIGURATION
// ======================================================

const CONTRACT_ADDRESS = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
const EXPECTED_CHAIN_ID = 31337;

const ABI = [
    "function owner() view returns (address)",

    "function getEquipment(uint256 id) view returns (uint256 equipmentId, string name, string status)",
    "function getAllEquipment() view returns (tuple(uint256 id, string name, string status)[] result)",
    "function getEquipmentCount() view returns (uint256)",

    "function createEquipment(uint256 id, string name)",
    "function updateEquipmentStatus(uint256 id, string newStatus)",

    "event EquipmentCreated(uint256 indexed id, string name)",
    "event EquipmentStatusChanged(uint256 indexed id, string status)",
    "event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)"
];

// ======================================================
// HELPERS
// ======================================================

function createCorrelationId() {
    if (typeof crypto !== "undefined" && crypto.randomUUID) {
        return crypto.randomUUID();
    }

    return `corr-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function getSafeError(error) {
    const code = error?.code ?? "UNKNOWN";

    if (
        code === 4001 ||
        code === "ACTION_REJECTED" ||
        error?.code === "ACTION_REJECTED"
    ) {
        return {
            code: "USER_REJECTED",
            message: "Пользователь отклонил запрос в кошельке."
        };
    }

    if (code === "CALL_EXCEPTION") {
        return {
            code: "CONTRACT_REVERT",
            message: error?.reason || "Смарт-контракт отклонил операцию."
        };
    }

    if (code === "NETWORK_ERROR") {
        return {
            code,
            message: "Ошибка подключения к сети блокчейна."
        };
    }

    if (code === "INSUFFICIENT_FUNDS") {
        return {
            code,
            message: "Недостаточно средств для выполнения транзакции."
        };
    }

    return {
        code: String(code),
        message:
            error?.shortMessage ||
            error?.reason ||
            "Не удалось выполнить операцию."
    };
}

// ======================================================
// APPLICATION
// ======================================================

export default function App() {

    // Wallet
    const [account, setAccount] = useState("");
    const [chainId, setChainId] = useState(null);
    const [provider, setProvider] = useState(null);
    const [signer, setSigner] = useState(null);
    const [contract, setContract] = useState(null);
    const [owner, setOwner] = useState("");

    // Equipment
    const [equipment, setEquipment] = useState([]);
    const [equipmentId, setEquipmentId] = useState("");
    const [equipmentName, setEquipmentName] = useState("");
    const [newStatus, setNewStatus] = useState("Active");

    // UI
    const [message, setMessage] = useState("");
    const [loading, setLoading] = useState(false);
    const [transactionStages, setTransactionStages] = useState([
        { name: "Запрос подписи", status: "WAITING" },
        { name: "Отправка транзакции", status: "WAITING" },
        { name: "Подтверждение блока", status: "WAITING" },
        { name: "Запись телеметрии", status: "WAITING" }
    ]);

    // Telemetry and security monitoring
    const [telemetry, setTelemetry] = useState([]);
    const [securityAlerts, setSecurityAlerts] = useState([]);

    // Refs
    const processedEvents = useRef(new Set());
    const pendingCorrelations = useRef(new Map());
    const detectionWindow = useRef([]);
    const alertCooldowns = useRef(new Map());

    // ==================================================
    // TELEMETRY ENGINE
    // ==================================================

    // Two threshold-based detection rules. Alerts are rate-limited per rule
    // so repeated events do not flood the dashboard.
    const evaluateDetectionRules = (entry) => {
        const now = Date.parse(entry.timestamp);
        const recent = [
            ...detectionWindow.current.filter(item => now - Date.parse(item.timestamp) <= 120000),
            entry
        ];
        detectionWindow.current = recent;

        const accessAttempts = recent.filter(item =>
            item.category === "APPLICATION_LOG" &&
            item.action === "PRIVILEGED_OPERATION_TEST" &&
            item.status === "REJECTED_UNAUTHORIZED" &&
            now - Date.parse(item.timestamp) <= 60000
        );

        const operationalFailures = recent.filter(item => {
            if (now - Date.parse(item.timestamp) > 120000) return false;
            if (item.category === "RPC_ERROR") return item.errorCode !== "USER_REJECTED";
            return item.category === "APPLICATION_LOG" &&
                item.status === "FAILED";
        });
        // Count distinct operations, not the RPC_ERROR + APPLICATION_LOG pair
        // that the same failed operation can generate.
        const accessAttemptCount = new Set(accessAttempts.map(item => item.correlationId)).size;
        const operationalFailureCount = new Set(operationalFailures.map(item => item.correlationId)).size;

        const rules = [
            {
                id: "ACCESS_VIOLATION",
                matched: accessAttemptCount >= 3,
                count: accessAttemptCount,
                threshold: "3 отклонённые привилегированные операции за 60 секунд",
                severity: "HIGH",
                title: "Обнаружены попытки нарушения доступа",
                source: "APPLICATION_LOG / PRIVILEGED_OPERATION_TEST",
                reaction: "Зафиксировать адрес и correlation ID, показать предупреждение оператору; проверить права кошелька и при необходимости временно заблокировать сессию."
            },
            {
                id: "OPERATIONAL_FAILURE",
                matched: operationalFailureCount >= 3,
                count: operationalFailureCount,
                threshold: "3 ошибки RPC или операции за 120 секунд",
                severity: "CRITICAL",
                title: "Обнаружен эксплуатационный сбой",
                source: "RPC_ERROR / APPLICATION_LOG со статусом FAILED",
                reaction: "Показать критическое уведомление, остановить новые управляющие операции до проверки, проверить RPC-узел, сеть и доступность контракта."
            }
        ];

        for (const rule of rules) {
            if (!rule.matched) continue;
            const lastAlert = alertCooldowns.current.get(rule.id) || 0;
            if (now - lastAlert < 300000) continue; // 5-minute deduplication window
            alertCooldowns.current.set(rule.id, now);

            const alert = {
                id: `${rule.id}-${now}`,
                ruleId: rule.id,
                title: rule.title,
                severity: rule.severity,
                source: rule.source,
                threshold: rule.threshold,
                observed: rule.count,
                reaction: rule.reaction,
                timestamp: new Date(now).toISOString(),
                correlationId: entry.correlationId
            };
            setSecurityAlerts(previous => [alert, ...previous].slice(0, 50));
            console.warn("[SECURITY ALERT]", alert);
        }
    };

    const addTelemetry = (category, details = {}, correlationId = createCorrelationId()) => {

        const entry = {
            id: createCorrelationId(),
            timestamp: new Date().toISOString(),
            category,
            correlationId,
            ...details
        };

        setTelemetry(previous => [entry, ...previous].slice(0, 200));
        evaluateDetectionRules(entry);

        console.info("[TELEMETRY]", entry);

        return correlationId;
    };

    const logApplication = (action, status, correlationId) => {

        return addTelemetry(
            "APPLICATION_LOG",
            {
                action,
                status
            },
            correlationId || createCorrelationId()
        );
    };

    const logRpcError = (error, operation, correlationId) => {

        const safe = getSafeError(error);

        addTelemetry(
            "RPC_ERROR",
            {
                operation,
                errorCode: safe.code,
                errorMessage: safe.message
            },
            correlationId || createCorrelationId()
        );
    };

    // ==================================================
    // TRANSACTION STAGES
    // ==================================================

    const resetStages = () => {

        setTransactionStages([
            { name: "Запрос подписи", status: "WAITING" },
            { name: "Отправка транзакции", status: "WAITING" },
            { name: "Подтверждение блока", status: "WAITING" },
            { name: "Запись телеметрии", status: "WAITING" }
        ]);
    };

    const updateStage = (index, status) => {

        setTransactionStages(previous =>
            previous.map((stage, i) =>
                i === index
                    ? { ...stage, status }
                    : stage
            )
        );
    };

    // ==================================================
    // WALLET CONNECTION
    // ==================================================

    const connectWallet = async () => {

        if (!window.ethereum) {
            setMessage("MetaMask не обнаружен.");
            logApplication("WALLET_CONNECT", "FAILED");
            return;
        }

        const correlationId = createCorrelationId();

        try {

            const browserProvider = new ethers.BrowserProvider(
                window.ethereum
            );

            const accounts = await browserProvider.send(
                "eth_requestAccounts",
                []
            );

            if (!accounts.length) {
                throw new Error("Wallet account not available");
            }

            const walletSigner = await browserProvider.getSigner();
            const network = await browserProvider.getNetwork();

            const address = await walletSigner.getAddress();

            const contractInstance = new ethers.Contract(
                CONTRACT_ADDRESS,
                ABI,
                walletSigner
            );

            setProvider(browserProvider);
            setSigner(walletSigner);
            setContract(contractInstance);
            setAccount(address);
            setChainId(Number(network.chainId));

            const contractOwner = await contractInstance.owner();
            setOwner(contractOwner);

            logApplication(
                "WALLET_CONNECT",
                "SUCCESS",
                correlationId
            );

            addTelemetry(
                "APPLICATION_LOG",
                {
                    action: "NETWORK_CONNECTED",
                    status: Number(network.chainId) === EXPECTED_CHAIN_ID
                        ? "EXPECTED_NETWORK"
                        : "WRONG_NETWORK",
                    chainId: Number(network.chainId)
                },
                correlationId
            );

            setMessage(
                Number(network.chainId) === EXPECTED_CHAIN_ID
                    ? "Кошелек подключен."
                    : "Кошелек подключен, но выбрана неправильная сеть."
            );

        } catch (error) {

            logRpcError(error, "WALLET_CONNECT", correlationId);

            logApplication(
                "WALLET_CONNECT",
                "FAILED",
                correlationId
            );

            setMessage(getSafeError(error).message);
        }
    };

    // ==================================================
    // WALLET DISCONNECTION
    // ==================================================

    const disconnectWallet = () => {

        setAccount("");
        setChainId(null);
        setProvider(null);
        setSigner(null);
        setContract(null);
        setOwner("");
        setEquipment([]);

        logApplication("WALLET_DISCONNECT", "SUCCESS");

        setMessage("Сеанс приложения завершен.");
    };

    // ==================================================
    // WALLET EVENTS
    // ==================================================

    useEffect(() => {

        if (!window.ethereum) return;

        const handleAccountsChanged = async accounts => {

            if (!accounts.length) {
                disconnectWallet();
                return;
            }

            try {
                // Rebuild signer-bound contract after MetaMask account switch.
                // Otherwise the UI shows the new address but transactions still use the old signer.
                const nextProvider = new ethers.BrowserProvider(window.ethereum);
                const nextSigner = await nextProvider.getSigner(accounts[0]);
                const nextContract = new ethers.Contract(
                    CONTRACT_ADDRESS,
                    ABI,
                    nextSigner
                );

                setProvider(nextProvider);
                setSigner(nextSigner);
                setContract(nextContract);
                setAccount(accounts[0]);

                logApplication(
                    "WALLET_ACCOUNT_CHANGED",
                    "SUCCESS"
                );
            } catch (error) {
                logRpcError(error, "WALLET_ACCOUNT_CHANGED");
                setMessage(getSafeError(error).message);
            }
        };

        const handleChainChanged = chain => {

            setChainId(Number(chain));

            logApplication(
                "NETWORK_CHANGED",
                "SUCCESS"
            );

            setMessage(
                Number(chain) === EXPECTED_CHAIN_ID
                    ? "Выбрана локальная сеть Hardhat."
                    : "Предупреждение: выбрана другая сеть."
            );
        };

        window.ethereum.on(
            "accountsChanged",
            handleAccountsChanged
        );

        window.ethereum.on(
            "chainChanged",
            handleChainChanged
        );

        return () => {

            window.ethereum.removeListener(
                "accountsChanged",
                handleAccountsChanged
            );

            window.ethereum.removeListener(
                "chainChanged",
                handleChainChanged
            );
        };

    }, []);

    // ==================================================
    // SMART CONTRACT EVENTS
    // ==================================================

    useEffect(() => {

        if (!contract) return;

        const recordContractEvent = (
            eventName,
            values,
            event
        ) => {

            // ethers v6 listener passes an EventPayload; the raw log is in event.log.
            const rawLog = event?.log ?? event;
            const txHash = rawLog?.transactionHash ?? event?.transactionHash;
            const logIndex = rawLog?.index ?? rawLog?.logIndex ?? event?.index;
            const blockNumber = rawLog?.blockNumber ?? event?.blockNumber;

            if (!txHash || logIndex === undefined || logIndex === null) {
                console.warn("Contract event has no transaction/log index; receipt parsing will handle it.", event);
                return;
            }

            const eventKey =
                `${txHash}-${logIndex}`;

            // Prevent duplicate records
            if (processedEvents.current.has(eventKey)) {
                return;
            }

            processedEvents.current.add(eventKey);

            const correlationId =
                pendingCorrelations.current.get(txHash) || txHash;

            addTelemetry(
                "CONTRACT_EVENT",
                {
                    eventName,
                    eventData: values,
                    transactionHash: txHash,
                    blockNumber,
                    logIndex
                },
                correlationId
            );
        };

        const createdHandler = (id, name, event) => {

            recordContractEvent(
                "EquipmentCreated",
                {
                    equipmentId: id.toString(),
                    name
                },
                event
            );
        };

        const statusHandler = (id, status, event) => {

            recordContractEvent(
                "EquipmentStatusChanged",
                {
                    equipmentId: id.toString(),
                    status
                },
                event
            );
        };

        const ownershipHandler = (previousOwner, newOwner, event) => {

            recordContractEvent(
                "OwnershipTransferred",
                {
                    previousOwner,
                    newOwner
                },
                event
            );
        };

        contract.on("EquipmentCreated", createdHandler);
        contract.on("EquipmentStatusChanged", statusHandler);
        contract.on("OwnershipTransferred", ownershipHandler);

        return () => {

            contract.off("EquipmentCreated", createdHandler);
            contract.off("EquipmentStatusChanged", statusHandler);
            contract.off("OwnershipTransferred", ownershipHandler);
        };

    }, [contract]);

    // ==================================================
    // NETWORK VALIDATION
    // ==================================================

    const validateConnection = () => {

        if (!contract || !account) {
            setMessage("Сначала подключите кошелек.");
            return false;
        }

        if (chainId !== EXPECTED_CHAIN_ID) {
            setMessage(
                `Неправильная сеть. Требуется chainId ${EXPECTED_CHAIN_ID}.`
            );

            return false;
        }

        return true;
    };

    // ==================================================
    // READ ALL EQUIPMENT
    // ==================================================

    const getAllEquipment = async () => {

        if (!validateConnection()) return;

        const correlationId = createCorrelationId();

        try {

            setLoading(true);

            const result = await contract.getAllEquipment();

            const formatted = result.map(item => ({
                id: item.id.toString(),
                name: item.name,
                status: item.status
            }));

            setEquipment(formatted);

            logApplication(
                "GET_ALL_EQUIPMENT",
                "SUCCESS",
                correlationId
            );

            setMessage(`Получено записей: ${formatted.length}`);

        } catch (error) {

            logRpcError(
                error,
                "GET_ALL_EQUIPMENT",
                correlationId
            );

            logApplication(
                "GET_ALL_EQUIPMENT",
                "FAILED",
                correlationId
            );

            setMessage(getSafeError(error).message);

        } finally {

            setLoading(false);
        }
    };

    // ==================================================
    // READ ONE EQUIPMENT
    // ==================================================

    const readEquipment = async () => {

        if (!validateConnection()) return;

        if (!equipmentId || Number(equipmentId) <= 0) {
            setMessage("Введите корректный ID оборудования.");
            return;
        }

        const correlationId = createCorrelationId();

        try {

            setLoading(true);

            const result = await contract.getEquipment(
                equipmentId
            );

            const item = {
                id: result.equipmentId.toString(),
                name: result.name,
                status: result.status
            };

            setEquipment(previous => [
                item,
                ...previous.filter(x => x.id !== item.id)
            ]);

            logApplication(
                "READ_EQUIPMENT",
                "SUCCESS",
                correlationId
            );

            setMessage(
                `Оборудование ${item.id}: ${item.name}, ${item.status}`
            );

        } catch (error) {

            logRpcError(
                error,
                "READ_EQUIPMENT",
                correlationId
            );

            logApplication(
                "READ_EQUIPMENT",
                "FAILED",
                correlationId
            );

            setMessage(getSafeError(error).message);

        } finally {

            setLoading(false);
        }
    };

    // ==================================================
    // WRITE TRANSACTION
    // ==================================================

    const executeTransaction = async (
        operation,
        args,
        operationName
    ) => {

        if (!validateConnection()) return;

        const correlationId = createCorrelationId();

        resetStages();

        setLoading(true);

        try {

            // Stage 1: signature request
            updateStage(0, "IN_PROGRESS");

            logApplication(
                operationName,
                "SIGNATURE_REQUESTED",
                correlationId
            );

            const txRequest = await operation(...args);

            updateStage(0, "SUCCESS");

            // Stage 2: transaction submitted
            updateStage(1, "IN_PROGRESS");

            pendingCorrelations.current.set(
                txRequest.hash,
                correlationId
            );

            logApplication(
                operationName,
                "TRANSACTION_SUBMITTED",
                correlationId
            );

            // Stage 3: wait for blockchain confirmation
            const receipt = await txRequest.wait();

            if (!receipt || receipt.status !== 1) {
                throw new Error("Transaction failed on blockchain");
            }

            updateStage(1, "SUCCESS");
            updateStage(2, "SUCCESS");

            // Receipt telemetry
            addTelemetry(
                "TRANSACTION_RECEIPT",
                {
                    transactionHash: receipt.hash,
                    blockNumber: receipt.blockNumber,
                    status: receipt.status,
                    gasUsed: receipt.gasUsed.toString(),
                    from: receipt.from,
                    to: receipt.to
                },
                correlationId
            );

            // Read smart-contract events from the confirmed transaction receipt.
            // This is the reliable fallback when the RPC provider does not deliver
            // live contract.on() notifications.
            let parsedContractEvents = 0;

            for (let logPosition = 0; logPosition < receipt.logs.length; logPosition++) {
                const log = receipt.logs[logPosition];

                try {
                    // Ignore logs emitted by other contracts.
                    if (
                        log.address &&
                        contract.target &&
                        log.address.toLowerCase() !== String(contract.target).toLowerCase()
                    ) {
                        continue;
                    }

                    // Pass only the fields required by Interface.parseLog.
                    const parsed = contract.interface.parseLog({
                        topics: log.topics,
                        data: log.data
                    });

                    if (!parsed) continue;

                    if (
                        parsed.name !== "EquipmentCreated" &&
                        parsed.name !== "EquipmentStatusChanged" &&
                        parsed.name !== "OwnershipTransferred"
                    ) {
                        continue;
                    }

                    const txHash = log.transactionHash || receipt.hash;
                    const logIndex = log.index ?? log.logIndex ?? logPosition;
                    const eventKey = `${txHash}-${logIndex}`;

                    if (processedEvents.current.has(eventKey)) {
                        continue;
                    }

                    processedEvents.current.add(eventKey);

                    const eventData = {};
                    parsed.fragment.inputs.forEach((input, index) => {
                        const value = parsed.args[index];
                        eventData[input.name || `arg${index}`] =
                            typeof value === "bigint" ? value.toString() : value;
                    });

                    // Normalize Equipment event fields for the UI.
                    if (parsed.name === "EquipmentCreated") {
                        eventData.equipmentId = String(
                            eventData.id ?? parsed.args[0].toString()
                        );
                        eventData.name = eventData.name ?? String(parsed.args[1]);
                    } else if (parsed.name === "EquipmentStatusChanged") {
                        eventData.equipmentId = String(
                            eventData.id ?? parsed.args[0].toString()
                        );
                        eventData.status = eventData.status ?? String(parsed.args[1]);
                    }

                    addTelemetry(
                        "CONTRACT_EVENT",
                        {
                            eventName: parsed.name,
                            eventData,
                            transactionHash: txHash,
                            blockNumber: log.blockNumber ?? receipt.blockNumber,
                            logIndex
                        },
                        correlationId
                    );

                    parsedContractEvents++;
                } catch (eventError) {
                    console.warn("Could not decode receipt log as Equipment event:", eventError);
                }
            }

            if (parsedContractEvents === 0) {
                console.warn(
                    "No Equipment smart-contract events were found in this transaction receipt.",
                    {
                        transactionHash: receipt.hash,
                        contractAddress: contract.target,
                        logCount: receipt.logs.length
                    }
                );
            }

            // Stage 4: telemetry recorded
            updateStage(3, "SUCCESS");

            logApplication(
                operationName,
                "CONFIRMED",
                correlationId
            );

            setMessage(
                `Транзакция подтверждена. Block: ${receipt.blockNumber}`
            );

            await getAllEquipment();

        } catch (error) {

            const safe = getSafeError(error);

            updateStage(
                0,
                safe.code === "USER_REJECTED"
                    ? "REJECTED"
                    : "FAILED"
            );

            logRpcError(
                error,
                operationName,
                correlationId
            );

            logApplication(
                operationName,
                safe.code === "USER_REJECTED"
                    ? "SIGNATURE_REJECTED"
                    : "FAILED",
                correlationId
            );

            setMessage(safe.message);

        } finally {

            setLoading(false);
        }
    };

    // ==================================================
    // CREATE EQUIPMENT
    // ==================================================

    const createEquipment = async () => {

        if (!equipmentId || Number(equipmentId) <= 0) {
            setMessage("Введите корректный ID.");
            return;
        }

        if (!equipmentName.trim()) {
            setMessage("Введите название оборудования.");
            return;
        }

        await executeTransaction(
            contract.createEquipment.bind(contract),
            [
                equipmentId,
                equipmentName.trim()
            ],
            "CREATE_EQUIPMENT"
        );
    };

    // ==================================================
    // UPDATE EQUIPMENT STATUS
    // ==================================================

    const updateEquipmentStatus = async () => {

        if (!equipmentId || Number(equipmentId) <= 0) {
            setMessage("Введите корректный ID.");
            return;
        }

        if (!newStatus.trim()) {
            setMessage("Введите новый статус.");
            return;
        }

        await executeTransaction(
            contract.updateEquipmentStatus.bind(contract),
            [
                equipmentId,
                newStatus.trim()
            ],
            "UPDATE_EQUIPMENT_STATUS"
        );
    };

    // ==================================================
    // PRIVILEGED OPERATION DEMONSTRATION
    // ==================================================

    const testUnauthorizedOperation = async () => {

        if (!validateConnection()) return;

        const correlationId = createCorrelationId();

        try {
            const currentOwner = await contract.owner();

            if (currentOwner.toLowerCase() === account.toLowerCase()) {
                logApplication(
                    "PRIVILEGED_OPERATION_TEST",
                    "OWNER_ACCOUNT_DETECTED",
                    correlationId
                );

                setMessage(
                    "Сейчас подключен владелец контракта. Переключите MetaMask на другой тестовый аккаунт Hardhat и повторите проверку."
                );
                return;
            }

            // staticCall executes the real Solidity permission check
            // without broadcasting a transaction or changing the ledger.
            await contract.createEquipment.staticCall(
                999999999,
                "Unauthorized access test"
            );

            logApplication(
                "PRIVILEGED_OPERATION_TEST",
                "UNEXPECTEDLY_ALLOWED",
                correlationId
            );

            setMessage(
                "Вызов неожиданно прошел. Проверьте, что подключен аккаунт, отличный от владельца."
            );

        } catch (error) {
            const safe = getSafeError(error);
            const isAccessDenied =
                safe.code === "CONTRACT_REVERT" ||
                String(error?.reason || "").includes("Access denied") ||
                String(error?.shortMessage || "").includes("execution reverted");

            if (isAccessDenied) {
                addTelemetry(
                    "APPLICATION_LOG",
                    {
                        action: "PRIVILEGED_OPERATION_TEST",
                        status: "REJECTED_UNAUTHORIZED",
                        errorMessage: safe.message || "Access denied: only owner"
                    },
                    correlationId
                );

                setMessage(
                    "Успешная демонстрация: смарт-контракт отклонил привилегированную операцию. Access denied: only owner."
                );
            } else {
                logRpcError(
                    error,
                    "PRIVILEGED_OPERATION_TEST",
                    correlationId
                );

                logApplication(
                    "PRIVILEGED_OPERATION_TEST",
                    "FAILED",
                    correlationId
                );

                setMessage(safe.message);
            }
        }
    };

    // ==================================================
    // TELEMETRY FILTERS
    // ==================================================

    const getTelemetryCount = category =>
        telemetry.filter(item => item.category === category).length;

    // ==================================================
    // UI
    // ==================================================

    return (

        <main style={styles.container}>

            <h1>Equipment Management DApp</h1>

            <p style={styles.subtitle}>
                Blockchain equipment registry and security telemetry
            </p>

            {/* WALLET */}

            <section style={styles.card}>

                <h2>Wallet Connection</h2>

                {!account ? (

                    <button
                        style={styles.button}
                        onClick={connectWallet}
                        disabled={loading}
                    >
                        Connect MetaMask
                    </button>

                ) : (

                    <>
                        <p>
                            <b>Address:</b> {account}
                        </p>

                        <p>
                            <b>Chain ID:</b> {chainId}
                        </p>

                        <p>
                            <b>Contract owner:</b> {owner}
                        </p>

                        <button
                            style={styles.secondaryButton}
                            onClick={disconnectWallet}
                        >
                            Disconnect Wallet
                        </button>
                    </>
                )}

                {chainId !== null && chainId !== EXPECTED_CHAIN_ID && (
                    <p style={styles.error}>
                        Wrong network. Expected chainId: {EXPECTED_CHAIN_ID}
                    </p>
                )}

            </section>

            {/* EQUIPMENT OPERATIONS */}

            <section style={styles.card}>

                <h2>Equipment Operations</h2>

                <label>Equipment ID</label>

                <input
                    style={styles.input}
                    type="number"
                    min="1"
                    value={equipmentId}
                    onChange={e => setEquipmentId(e.target.value)}
                    placeholder="Enter equipment ID"
                />

                <label>Equipment Name</label>

                <input
                    style={styles.input}
                    value={equipmentName}
                    onChange={e => setEquipmentName(e.target.value)}
                    placeholder="Enter equipment name"
                />

                <div style={styles.buttonGroup}>

                    <button
                        style={styles.button}
                        onClick={createEquipment}
                        disabled={loading || !account}
                    >
                        Create Equipment
                    </button>

                    <button
                        style={styles.secondaryButton}
                        onClick={readEquipment}
                        disabled={loading || !account}
                    >
                        Read Equipment
                    </button>

                </div>

                <label>New Equipment Status</label>

                <select
                    style={styles.input}
                    value={newStatus}
                    onChange={e => setNewStatus(e.target.value)}
                >
                    <option value="Active">Active</option>
                    <option value="Maintenance">Maintenance</option>
                    <option value="Inactive">Inactive</option>
                </select>

                <button
                    style={styles.button}
                    onClick={updateEquipmentStatus}
                    disabled={loading || !account}
                >
                    Update Equipment Status
                </button>

                <button
                    style={styles.secondaryButton}
                    onClick={getAllEquipment}
                    disabled={loading || !account}
                >
                    Get All Equipment
                </button>

            </section>

            {/* PRIVILEGED OPERATION */}

            <section style={styles.card}>

                <h2>Access Control Test</h2>

                <p>
                    Переключите MetaMask на тестовый аккаунт Hardhat, который
                    не является владельцем контракта. Проверка вызовет реальный
                    Solidity require через staticCall без отправки транзакции.
                </p>

                <button
                    style={styles.dangerButton}
                    onClick={testUnauthorizedOperation}
                    disabled={loading || !account}
                >
                    Test Unauthorized Operation
                </button>

            </section>

            {/* TRANSACTION STAGES */}

            <section style={styles.card}>

                <h2>Transaction Execution Stages</h2>

                {transactionStages.map((stage, index) => (

                    <div
                        key={index}
                        style={styles.stage}
                    >

                        <span>
                            {index + 1}. {stage.name}
                        </span>

                        <b style={{
                            color:
                                stage.status === "SUCCESS"
                                    ? "#16a34a"
                                    : stage.status === "FAILED" ||
                                      stage.status === "REJECTED"
                                        ? "#dc2626"
                                        : stage.status === "IN_PROGRESS"
                                            ? "#d97706"
                                            : "#64748b"
                        }}>
                            {stage.status}
                        </b>

                    </div>

                ))}

            </section>

            {/* STATUS */}

            {message && (

                <section style={styles.card}>
                    <h2>Application Status</h2>
                    <p>{message}</p>
                </section>

            )}

            {/* EQUIPMENT TABLE */}

            <section style={styles.card}>

                <h2>Equipment Registry</h2>

                {equipment.length === 0 ? (

                    <p>No equipment records loaded.</p>

                ) : (

                    <div style={{ overflowX: "auto" }}>

                        <table style={styles.table}>

                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Name</th>
                                    <th>Status</th>
                                </tr>
                            </thead>

                            <tbody>

                                {equipment.map(item => (

                                    <tr key={item.id}>
                                        <td>{item.id}</td>
                                        <td>{item.name}</td>
                                        <td>{item.status}</td>
                                    </tr>

                                ))}

                            </tbody>

                        </table>

                    </div>

                )}

            </section>

            {/* SMART CONTRACT EVENTS */}

            <section style={styles.card}>
                <h2>Smart Contract Events</h2>
                <p style={styles.subtitle}>
                    События смарт-контракта Equipment с идентификаторами транзакций и блоков.
                </p>

                <div style={styles.telemetryGrid}>
                    <div style={styles.metric}>
                        <h3>EquipmentCreated</h3>
                        <p>Создание нового оборудования</p>
                    </div>
                    <div style={styles.metric}>
                        <h3>EquipmentStatusChanged</h3>
                        <p>Изменение статуса оборудования</p>
                    </div>
                </div>

                <div style={styles.telemetryList}>
                    {telemetry.filter(item =>
                        item.category === "CONTRACT_EVENT" &&
                        ["EquipmentCreated", "EquipmentStatusChanged"].includes(item.eventName)
                    ).length === 0 ? (
                        <p>Событий пока нет. Создайте оборудование или измените его статус.</p>
                    ) : (
                        telemetry
                            .filter(item =>
                                item.category === "CONTRACT_EVENT" &&
                                ["EquipmentCreated", "EquipmentStatusChanged"].includes(item.eventName)
                            )
                            .map(item => (
                                <article key={item.id} style={styles.telemetryItem}>
                                    <div style={styles.telemetryHeader}>
                                        <b>{item.eventName}</b>
                                        <span>{item.timestamp}</span>
                                    </div>
                                    <p><b>Record ID:</b> {item.id}</p>
                                    <p style={styles.correlation}>
                                        <b>Correlation ID:</b> {item.correlationId}
                                    </p>
                                    <p><b>Equipment ID:</b> {item.eventData?.equipmentId ?? item.eventData?.id ?? "N/A"}</p>
                                    {item.eventData?.name !== undefined && (
                                        <p><b>Name:</b> {item.eventData.name}</p>
                                    )}
                                    {item.eventData?.status !== undefined && (
                                        <p><b>Status:</b> {item.eventData.status}</p>
                                    )}
                                    <p style={styles.correlation}>
                                        <b>Transaction Hash:</b> {item.transactionHash || "N/A"}
                                    </p>
                                    <p><b>Block Number:</b> {item.blockNumber ?? "N/A"}</p>
                                    <p><b>Log Index:</b> {item.logIndex ?? "N/A"}</p>
                                </article>
                            ))
                    )}
                </div>
            </section>

            {/* SECURITY MONITORING / DETECTION RULES */}

            <section style={styles.card}>
                <h2>Security Monitoring</h2>
                <p style={styles.subtitle}>Два правила обнаружения с временными окнами и защитой от повторных уведомлений (cooldown 5 минут на каждое правило).</p>

                <div style={styles.telemetryGrid}>
                    <div style={styles.metric}>
                        <h3>HIGH</h3>
                        <p><b>Нарушение доступа</b></p>
                        <p>3 отказа в привилегированной операции за 60 секунд</p>
                        <p>Источник: APPLICATION_LOG / REJECTED_UNAUTHORIZED</p>
                        <p>Реакция: уведомить оператора и проверить права кошелька</p>
                    </div>
                    <div style={styles.metric}>
                        <h3>CRITICAL</h3>
                        <p><b>Эксплуатационный сбой</b></p>
                        <p>3 ошибки RPC/операции за 120 секунд</p>
                        <p>Источник: RPC_ERROR / APPLICATION_LOG FAILED</p>
                        <p>Реакция: предупредить оператора и приостановить новые управляющие операции до проверки</p>
                    </div>
                </div>

                <h3>Сработавшие уведомления ({securityAlerts.length})</h3>
                <div style={styles.telemetryList}>
                    {securityAlerts.length === 0 ? (
                        <p>Срабатываний пока нет. Для проверки правила доступа выполните тест отказа в привилегированной операции 3 раза за 60 секунд.</p>
                    ) : securityAlerts.map(alert => (
                        <article key={alert.id} style={styles.telemetryItem}>
                            <div style={styles.telemetryHeader}>
                                <b>{alert.title}</b>
                                <span>{alert.severity} · {alert.timestamp}</span>
                            </div>
                            <p><b>Rule:</b> {alert.ruleId}</p>
                            <p><b>Источник:</b> {alert.source}</p>
                            <p><b>Порог:</b> {alert.threshold}</p>
                            <p><b>Наблюдалось:</b> {alert.observed}</p>
                            <p><b>Реакция:</b> {alert.reaction}</p>
                            <p style={styles.correlation}><b>Correlation ID:</b> {alert.correlationId}</p>
                        </article>
                    ))}
                </div>
            </section>

            {/* TELEMETRY DASHBOARD */}

            <section style={styles.card}>

                <h2>System Telemetry</h2>

                <div style={styles.telemetryGrid}>

                    <div style={styles.metric}>
                        <h3>{getTelemetryCount("CONTRACT_EVENT")}</h3>
                        <p>Contract Events</p>
                    </div>

                    <div style={styles.metric}>
                        <h3>{getTelemetryCount("TRANSACTION_RECEIPT")}</h3>
                        <p>Transaction Receipts</p>
                    </div>

                    <div style={styles.metric}>
                        <h3>{getTelemetryCount("RPC_ERROR")}</h3>
                        <p>RPC Errors</p>
                    </div>

                    <div style={styles.metric}>
                        <h3>{getTelemetryCount("APPLICATION_LOG")}</h3>
                        <p>Application Logs</p>
                    </div>

                </div>

                <p>
                    <b>Total records:</b> {telemetry.length}
                </p>

                <div style={styles.buttonGroup}>

                    <button
                        style={styles.secondaryButton}
                        onClick={() => {
                            const json = JSON.stringify(
                                telemetry,
                                null,
                                2
                            );

                            const blob = new Blob(
                                [json],
                                { type: "application/json" }
                            );

                            const url = URL.createObjectURL(blob);
                            const link = document.createElement("a");

                            link.href = url;
                            link.download = "equipment-telemetry.json";
                            link.click();

                            URL.revokeObjectURL(url);

                            logApplication(
                                "TELEMETRY_EXPORT",
                                "SUCCESS"
                            );
                        }}
                    >
                        Export Telemetry JSON
                    </button>

                </div>

                <div style={styles.telemetryList}>

                    {telemetry.length === 0 ? (

                        <p>No telemetry records yet.</p>

                    ) : (

                        telemetry.map(item => (

                            <article
                                key={item.id}
                                style={styles.telemetryItem}
                            >

                                <div style={styles.telemetryHeader}>
                                    <b>{item.category}</b>
                                    <span>{item.timestamp}</span>
                                </div>

                                <p>
                                    <b>Record ID:</b> {item.id}
                                </p>

                                <p style={styles.correlation}>
                                    <b>Correlation ID:</b>{" "}
                                    {item.correlationId}
                                </p>

                                <pre style={styles.pre}>
                                    {JSON.stringify(
                                        item,
                                        null,
                                        2
                                    )}
                                </pre>

                            </article>

                        ))

                    )}

                </div>

            </section>

            <footer style={styles.footer}>
                Equipment DApp | Hardhat Local Network | Chain ID 31337
            </footer>

        </main>
    );
}

// ======================================================
// STYLES
// ======================================================

const styles = {

    container: {
        maxWidth: "1100px",
        margin: "0 auto",
        padding: "30px 20px",
        fontFamily: "Arial, sans-serif",
        color: "#1e293b",
        background: "#f8fafc",
        minHeight: "100vh"
    },

    subtitle: {
        color: "#64748b",
        marginBottom: "25px"
    },

    card: {
        background: "#ffffff",
        border: "1px solid #e2e8f0",
        borderRadius: "12px",
        padding: "22px",
        marginBottom: "20px",
        boxShadow: "0 2px 8px rgba(0,0,0,0.04)"
    },

    input: {
        display: "block",
        width: "100%",
        boxSizing: "border-box",
        padding: "11px",
        margin: "8px 0 16px",
        border: "1px solid #cbd5e1",
        borderRadius: "6px",
        fontSize: "14px"
    },

    button: {
        background: "#2563eb",
        color: "#ffffff",
        border: "none",
        padding: "11px 16px",
        borderRadius: "6px",
        cursor: "pointer",
        margin: "5px",
        fontWeight: "bold"
    },

    secondaryButton: {
        background: "#475569",
        color: "#ffffff",
        border: "none",
        padding: "11px 16px",
        borderRadius: "6px",
        cursor: "pointer",
        margin: "5px",
        fontWeight: "bold"
    },

    dangerButton: {
        background: "#dc2626",
        color: "#ffffff",
        border: "none",
        padding: "11px 16px",
        borderRadius: "6px",
        cursor: "pointer",
        margin: "5px",
        fontWeight: "bold"
    },

    buttonGroup: {
        display: "flex",
        flexWrap: "wrap",
        gap: "8px",
        marginTop: "10px"
    },

    error: {
        color: "#dc2626",
        fontWeight: "bold"
    },

    stage: {
        display: "flex",
        justifyContent: "space-between",
        padding: "12px",
        borderBottom: "1px solid #e2e8f0"
    },

    table: {
        width: "100%",
        borderCollapse: "collapse",
        textAlign: "left"
    },

    telemetryGrid: {
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
        gap: "12px",
        margin: "20px 0"
    },

    metric: {
        background: "#eff6ff",
        border: "1px solid #bfdbfe",
        borderRadius: "8px",
        padding: "12px",
        textAlign: "center"
    },

    telemetryList: {
        display: "flex",
        flexDirection: "column",
        gap: "12px",
        marginTop: "20px"
    },

    telemetryItem: {
        background: "#f8fafc",
        border: "1px solid #e2e8f0",
        borderRadius: "8px",
        padding: "14px",
        overflowWrap: "anywhere"
    },

    telemetryHeader: {
        display: "flex",
        justifyContent: "space-between",
        flexWrap: "wrap",
        gap: "8px",
        marginBottom: "10px"
    },

    correlation: {
        overflowWrap: "anywhere",
        fontSize: "13px"
    },

    pre: {
        whiteSpace: "pre-wrap",
        overflowWrap: "anywhere",
        background: "#e2e8f0",
        padding: "10px",
        borderRadius: "6px",
        fontSize: "12px"
    },

    footer: {
        textAlign: "center",
        color: "#64748b",
        padding: "20px"
    }
};
