enable_testing()

set(KarboTests_INCLUDE_DIRS
    ${Karbo_INCLUDE_DIRS}
    "${CMAKE_CURRENT_LIST_DIR}")

# KarboTests

add_custom_target(KarboTests DEPENDS
    #KarboTests::CoreTests
    KarboTests::CryptoTests
    KarboTests::DifficultyTests
    KarboTests::HashTargetTests
    KarboTests::HashTests
    KarboTests::IntegrationTests
    KarboTests::NodeRpcProxyTests
    KarboTests::PerformanceTests
    KarboTests::SystemTests
    KarboTests::TransfersTests
    #KarboTests::UnitTests
)

# KarboTests::CoreTests

set(KarboTests_CoreTests_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/AccountBoostSerialization.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/BlockReward.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/BlockReward.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/BlockValidation.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/BlockValidation.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/BoostSerializationHelper.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/ChainSplit1.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/ChainSplit1.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/ChainSwitch1.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/ChainSwitch1.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/Chaingen.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/Chaingen.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/Chaingen001.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/Chaingen001.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/ChaingenMain.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/CryptoNoteBoostSerialization.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/DoubleSpend.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/DoubleSpend.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/IntegerOverflow.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/IntegerOverflow.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/RandomOuts.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/RandomOuts.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/RingSignature.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/RingSignature.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/TestGenerator.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/TransactionBuilder.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/TransactionBuilder.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/TransactionTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/TransactionTests.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/TransactionValidation.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/TransactionValidation.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/UnorderedContainersBoostSerialization.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/Upgrade.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/Upgrade.h"
    "${CMAKE_CURRENT_LIST_DIR}/CoreTests/double_spend.inl")

set(KarboTests_CoreTests_LIBS "")

add_executable(KarboTests_CoreTests ${KarboTests_CoreTests_SOURCES})
add_executable(KarboTests::CoreTests ALIAS KarboTests_CoreTests)
target_include_directories(KarboTests_CoreTests PRIVATE ${KarboTests_INCLUDE_DIRS})
target_link_libraries(KarboTests_CoreTests PRIVATE ${KarboTests_CoreTests_LIBS})
set_target_properties(KarboTests_CoreTests PROPERTIES
    OUTPUT_NAME "core_tests"
    EXCLUDE_FROM_ALL TRUE
    EXCLUDE_FROM_DEFAULT_BUILD TRUE)

add_test(NAME CoreTests
         COMMAND core_tests --generate_and_play_test_data)

# KarboTests::CryptoTests

set(KarboTests_CryptoTests_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/CryptoTests/crypto-ops-data.c"
    "${CMAKE_CURRENT_LIST_DIR}/CryptoTests/crypto-ops.c"
    "${CMAKE_CURRENT_LIST_DIR}/CryptoTests/crypto-tests.h"
    "${CMAKE_CURRENT_LIST_DIR}/CryptoTests/crypto.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CryptoTests/hash.c"
    "${CMAKE_CURRENT_LIST_DIR}/CryptoTests/main.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/CryptoTests/random.c")

set(KarboTests_CryptoTests_LIBS "")

add_executable(KarboTests_CryptoTests ${KarboTests_CryptoTests_SOURCES})
add_executable(KarboTests::CryptoTests ALIAS KarboTests_CryptoTests)
target_include_directories(KarboTests_CryptoTests PRIVATE ${KarboTests_INCLUDE_DIRS})
target_link_libraries(KarboTests_CryptoTests PRIVATE ${KarboTests_CryptoTests_LIBS})
set_target_properties(KarboTests_CryptoTests PROPERTIES OUTPUT_NAME "crypto_tests")

add_test(NAME CryptoTests
         COMMAND crypto_tests ${CMAKE_CURRENT_LIST_DIR}/CryptoTests/tests.txt)

# KarboTests::Data (skipped, not a library or executable target)

# KarboTests::DifficultyTests

set(KarboTests_DifficultyTests_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/DifficultyTests/Difficulty.cpp")

set(KarboTests_DifficultyTests_LIBS
    Karbo::Logging
    Karbo::CryptoNoteCore)

add_executable(KarboTests_DifficultyTests ${KarboTests_DifficultyTests_SOURCES})
add_executable(KarboTests::DifficultyTests ALIAS KarboTests_DifficultyTests)
target_include_directories(KarboTests_DifficultyTests PRIVATE ${KarboTests_INCLUDE_DIRS})
target_link_libraries(KarboTests_DifficultyTests PRIVATE ${KarboTests_DifficultyTests_LIBS})
set_target_properties(KarboTests_DifficultyTests PROPERTIES OUTPUT_NAME "difficulty_tests")

add_test(NAME DifficultyTests
         COMMAND difficulty_tests ${CMAKE_CURRENT_LIST_DIR}/DifficultyTests/data.txt)

# KarboTests::HashTargetTests

set(KarboTests_HashTargetTests_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/HashTargetTests/HashTarget.cpp")

set(KarboTests_HashTargetTests_LIBS
    Karbo::CryptoNoteCore)

add_executable(KarboTests_HashTargetTests ${KarboTests_HashTargetTests_SOURCES})
add_executable(KarboTests::HashTargetTests ALIAS KarboTests_HashTargetTests)
target_include_directories(KarboTests_HashTargetTests PRIVATE ${KarboTests_INCLUDE_DIRS})
target_link_libraries(KarboTests_HashTargetTests PRIVATE ${KarboTests_HashTargetTests_LIBS})
set_target_properties(KarboTests_HashTargetTests PROPERTIES OUTPUT_NAME "hash_target_tests")

add_test(NAME HashTargetTests
         COMMAND hash_target_tests)

# KarboTests::HashTests

set(KarboTests_HashTests_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/HashTests/main.cpp")

set(KarboTests_HashTests_LIBS
    Karbo::Crypto)

add_executable(KarboTests_HashTests ${KarboTests_HashTests_SOURCES})
add_executable(KarboTests::HashTests ALIAS KarboTests_HashTests)
target_include_directories(KarboTests_HashTests PRIVATE ${KarboTests_INCLUDE_DIRS})
target_link_libraries(KarboTests_HashTests PRIVATE ${KarboTests_HashTests_LIBS})
set_target_properties(KarboTests_HashTests PROPERTIES OUTPUT_NAME "hash_tests")

foreach(hash IN ITEMS extra-blake extra-groestl extra-jh extra-skein fast slow tree)
    add_test(NAME HashTests-${hash}
             COMMAND hash_tests ${hash} ${CMAKE_CURRENT_LIST_DIR}/HashTests/tests-${hash}.txt)
endforeach()

# KarboTests::IntegrationTestLib

set(KarboTests_IntegrationTestLib_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/BaseFunctionalTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/BaseFunctionalTests.h"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/InProcTestNode.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/InProcTestNode.h"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/Logger.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/Logger.h"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/NetworkConfiguration.h"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/NodeCallback.h"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/NodeObserver.h"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/ObservableValue.h"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/Process.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/Process.h"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/RPCTestNode.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/RPCTestNode.h"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/TestNetwork.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/TestNetwork.h"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/TestNode.h"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/TestWalletLegacy.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTestLib/TestWalletLegacy.h")

set(KarboTests_IntegrationTestLib_LIBS
    Karbo::InProcessNode)

add_library(KarboTests_IntegrationTestLib ${KarboTests_IntegrationTestLib_SOURCES})
add_library(KarboTests::IntegrationTestLib ALIAS KarboTests_IntegrationTestLib)
target_include_directories(KarboTests_IntegrationTestLib PRIVATE ${KarboTests_INCLUDE_DIRS})
target_link_libraries(KarboTests_IntegrationTestLib PRIVATE ${KarboTests_IntegrationTestLib_LIBS})

# KarboTests::IntegrationTests

set(KarboTests_IntegrationTests_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTests/BaseTests.h"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTests/IntegrationTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTests/MultiVersion.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTests/Node.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTests/WalletLegacyObserver.h"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTests/WalletLegacyTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/IntegrationTests/main.cpp")

set(KarboTests_IntegrationTests_LIBS
    Boost::program_options
    GTest::main
    Karbo::CryptoNoteCore
    Karbo::CryptoNoteProtocol
    Karbo::Http
    Karbo::InProcessNode
    Karbo::Logging
    Karbo::Rpc
    Karbo::Serialization
    Karbo::System
    KarboTests::IntegrationTestLib)

add_executable(KarboTests_IntegrationTests ${KarboTests_IntegrationTests_SOURCES})
add_executable(KarboTests::IntegrationTests ALIAS KarboTests_IntegrationTests)
target_include_directories(KarboTests_IntegrationTests PRIVATE ${KarboTests_INCLUDE_DIRS})
target_link_libraries(KarboTests_IntegrationTests PRIVATE ${KarboTests_IntegrationTests_LIBS})
set_target_properties(KarboTests_IntegrationTests PROPERTIES OUTPUT_NAME "integration_tests")

# KarboTests::NodeRpcProxyTests

set(KarboTests_NodeRpcProxyTests_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/NodeRpcProxyTests/NodeRpcProxyTests.cpp")

set(KarboTests_NodeRpcProxyTests_LIBS
    Karbo::Common
    Karbo::Logging
    Karbo::NodeRpcProxy
    Karbo::Rpc
    Karbo::Serialization)

add_executable(KarboTests_NodeRpcProxyTests ${KarboTests_NodeRpcProxyTests_SOURCES})
add_executable(KarboTests::NodeRpcProxyTests ALIAS KarboTests_NodeRpcProxyTests)
target_include_directories(KarboTests_NodeRpcProxyTests PRIVATE ${KarboTests_INCLUDE_DIRS})
target_link_libraries(KarboTests_NodeRpcProxyTests PRIVATE ${KarboTests_NodeRpcProxyTests_LIBS})
set_target_properties(KarboTests_NodeRpcProxyTests PROPERTIES OUTPUT_NAME "node_rpc_proxy_tests")

# KarboTests::PerformanceTests

set(KarboTests_PerformanceTests_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/PerformanceTests/CheckRingSignature.h"
    "${CMAKE_CURRENT_LIST_DIR}/PerformanceTests/ConstructTransaction.h"
    "${CMAKE_CURRENT_LIST_DIR}/PerformanceTests/CryptoNoteSlowHash.h"
    "${CMAKE_CURRENT_LIST_DIR}/PerformanceTests/DerivePublicKey.h"
    "${CMAKE_CURRENT_LIST_DIR}/PerformanceTests/DeriveSecretKey.h"
    "${CMAKE_CURRENT_LIST_DIR}/PerformanceTests/GenerateKeyDerivation.h"
    "${CMAKE_CURRENT_LIST_DIR}/PerformanceTests/GenerateKeyImage.h"
    "${CMAKE_CURRENT_LIST_DIR}/PerformanceTests/GenerateKeyImageHelper.h"
    "${CMAKE_CURRENT_LIST_DIR}/PerformanceTests/IsOutToAccount.h"
    "${CMAKE_CURRENT_LIST_DIR}/PerformanceTests/MultiTransactionTestBase.h"
    "${CMAKE_CURRENT_LIST_DIR}/PerformanceTests/PerformanceTests.h"
    "${CMAKE_CURRENT_LIST_DIR}/PerformanceTests/PerformanceUtils.h"
    "${CMAKE_CURRENT_LIST_DIR}/PerformanceTests/SingleTransactionTestBase.h"
    "${CMAKE_CURRENT_LIST_DIR}/PerformanceTests/main.cpp")

set(KarboTests_PerformanceTests_LIBS
    Boost::chrono
    Karbo::CryptoNoteCore
    Karbo::Logging)

add_executable(KarboTests_PerformanceTests ${KarboTests_PerformanceTests_SOURCES})
add_executable(KarboTests::PerformanceTests ALIAS KarboTests_PerformanceTests)
target_include_directories(KarboTests_PerformanceTests PRIVATE ${KarboTests_INCLUDE_DIRS})
target_link_libraries(KarboTests_PerformanceTests PRIVATE ${KarboTests_PerformanceTests_LIBS})
set_target_properties(KarboTests_PerformanceTests PROPERTIES OUTPUT_NAME "performance_tests")

# KarboTests::SystemTests

set(KarboTests_SystemTests_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/ContextGroupTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/ContextGroupTimeoutTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/ContextTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/DispatcherTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/ErrorMessageTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/EventLockTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/EventTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/Ipv4AddressTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/Ipv4ResolverTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/OperationTimeoutTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/RemoteContextTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/TcpConnectionTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/TcpConnectorTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/TcpListenerTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/TimerTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/SystemTests/main.cpp")

set(KarboTests_SystemTests_LIBS
    GTest::main
    Karbo::System)

add_executable(KarboTests_SystemTests ${KarboTests_SystemTests_SOURCES})
add_executable(KarboTests::SystemTests ALIAS KarboTests_SystemTests)
target_include_directories(KarboTests_SystemTests PRIVATE ${KarboTests_INCLUDE_DIRS})
target_link_libraries(KarboTests_SystemTests PRIVATE ${KarboTests_SystemTests_LIBS})
set_target_properties(KarboTests_SystemTests PROPERTIES OUTPUT_NAME "system_tests")

add_test(NAME SystemTests
         COMMAND system_tests)

# KarboTests::TestGenerator

set(KarboTests_TestGenerator_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/TestGenerator/TestGenerator.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/TestGenerator/TestGenerator.h")

set(KarboTests_TestGenerator_LIBS "")

add_library(KarboTests_TestGenerator ${KarboTests_TestGenerator_SOURCES})
add_library(KarboTests::TestGenerator ALIAS KarboTests_TestGenerator)
target_include_directories(KarboTests_TestGenerator PRIVATE ${KarboTests_INCLUDE_DIRS})
target_link_libraries(KarboTests_TestGenerator PRIVATE ${KarboTests_TestGenerator_LIBS})

# KarboTests::TransfersTests

set(KarboTests_TransfersTests_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/TransfersTests/Globals.h"
    "${CMAKE_CURRENT_LIST_DIR}/TransfersTests/TestNodeRpcProxy.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/TransfersTests/TestTxPoolSync.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/TransfersTests/Tests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/TransfersTests/main.cpp")

set(KarboTests_TransfersTests_LIBS
    Boost::program_options
    GTest::main
    Karbo::Common
    Karbo::CryptoNoteCore
    Karbo::CryptoNoteProtocol
    Karbo::InProcessNode
    Karbo::Logging
    Karbo::Rpc
    Karbo::Serialization
    Karbo::System
    Karbo::Transfers
    KarboTests::IntegrationTestLib)

add_executable(KarboTests_TransfersTests ${KarboTests_TransfersTests_SOURCES})
add_executable(KarboTests::TransfersTests ALIAS KarboTests_TransfersTests)
target_include_directories(KarboTests_TransfersTests PRIVATE ${KarboTests_INCLUDE_DIRS})
target_link_libraries(KarboTests_TransfersTests PRIVATE ${KarboTests_TransfersTests_LIBS})
set_target_properties(KarboTests_TransfersTests PROPERTIES OUTPUT_NAME "transfers_tests")

add_test(NAME TransfersTests
         COMMAND transfers_tests)

# KarboTests::UnitTests

set(KarboTests_UnitTests_SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/ArrayRefTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/ArrayViewTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/Base58.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/BinarySerializationCompatibility.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/BlockReward.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/BlockingQueue.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/Chacha8.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/Checkpoints.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/DecomposeAmountIntoDigits.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/EventWaiter.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/EventWaiter.h"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/ICoreStub.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/ICoreStub.h"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/ICryptoNoteProtocolQueryStub.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/ICryptoNoteProtocolQueryStub.h"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/INodeStubs.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/INodeStubs.h"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/MulDiv.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/ParseAmount.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/PaymentGateTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/Serialization.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/SerializationKV.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/Shuffle.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/StringBufferTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/StringViewTests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestBcS.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestBlockchainExplorer.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestBlockchainGenerator.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestBlockchainGenerator.h"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestCurrency.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestFileMappedVector.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestFormatUtils.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestInprocessNode.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestJsonValue.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestMessageQueue.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestPath.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestPeerlist.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestProtocolPack.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestTransactionPoolDetach.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestTransfers.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestTransfersConsumer.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestTransfersContainer.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestTransfersContainerKeyImage.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestTransfersSubscription.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestUpgradeDetector.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestWallet.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestWalletLegacy.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TestWalletService.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TransactionApi.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TransactionApiHelpers.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TransactionApiHelpers.h"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TransactionPool.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/TransfersObserver.h"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/UnitTestsUtils.h"
    "${CMAKE_CURRENT_LIST_DIR}/UnitTests/main.cpp")

set(KarboTests_UnitTests_LIBS
    GTest::main)

add_executable(KarboTests_UnitTests ${KarboTests_UnitTests_SOURCES})
add_executable(KarboTests::UnitTests ALIAS KarboTests_UnitTests)
target_include_directories(KarboTests_UnitTests PRIVATE ${KarboTests_INCLUDE_DIRS})
target_link_libraries(KarboTests_UnitTests PRIVATE ${KarboTests_UnitTests_LIBS})
set_target_properties(KarboTests_UnitTests PROPERTIES
    OUTPUT_NAME "unit_tests"
    EXCLUDE_FROM_ALL TRUE
    EXCLUDE_FROM_DEFAULT_BUILD TRUE)

add_test(NAME UnitTests
         COMMAND unit_tests)
