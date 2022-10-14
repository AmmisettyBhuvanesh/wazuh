#include "cmds/cmdRun.hpp"

#include <atomic>
#include <csignal>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <api/api.hpp>
#include <api/catalog/catalog.hpp>
#include <api/catalog/commands.hpp>
#include <builder/builder.hpp>
#include <builder/register.hpp>
#include <hlp/hlp.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <rxbk/rxFactory.hpp>
#include <store/drivers/fileDriver.hpp>
#include <server/engineServer.hpp>

#include "base/utils/getExceptionStack.hpp"
#include "stackExecutor.hpp"
#include "register.hpp"

cmd::StackExecutor g_exitHanlder {};

namespace
{
constexpr auto WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 1000000;


// variables for handling threads
std::atomic<bool> gs_doRun = true;
std::vector<std::thread> gs_threadList;

void sigint_handler(const int signum)
{
    // Inform threads that they must exit
    gs_doRun = false;

    for (auto& t : gs_threadList)
    {
        t.join();
    };

    g_exitHanlder.execute();

    // TODO: this should not be necessary, but server threads are not terminating.
    exit(0);
}
} // namespace

namespace cmd
{
void run(const std::string& kvdbPath,
         const std::string& eventEndpoint,
         const std::string& apiEndpoint,
         const int queueSize,
         const int threads,
         const std::string& fileStorage,
         const std::string& environment,
         const int logLevel)
{

    // Set Crt+C handler
    {
        // Set the signal handler for SIGINT
        struct sigaction sigIntHandler;
        sigIntHandler.sa_handler = sigint_handler;
        sigemptyset(&sigIntHandler.sa_mask);
        sigIntHandler.sa_flags = 0;
        sigaction(SIGINT, &sigIntHandler, nullptr);
    }
    // Init logging
    logging::LoggingConfig logConfig;
    auto badLogLevel = false;
    switch (logLevel)
    {
        case 0: logConfig.logLevel = logging::LogLevel::Debug; break;
        case 1: logConfig.logLevel = logging::LogLevel::Info; break;
        case 2: logConfig.logLevel = logging::LogLevel::Warn; break;
        case 3: logConfig.logLevel = logging::LogLevel::Error; break;
        default: badLogLevel = true; logging::LogLevel::Error;
    }
    logging::loggingInit(logConfig);
    g_exitHanlder.add([]() { logging::loggingTerm(); });
    if (badLogLevel)
    {
        WAZUH_LOG_WARN("Invalid log level [{}]: Log level setted to [Error]", logLevel);
    }
    WAZUH_LOG_INFO("Logging initialized");

    // Init modules
    std::shared_ptr<store::FileDriver> store;
    std::shared_ptr<builder::Builder> builder;
    std::shared_ptr<api::catalog::Catalog> catalog;
    std::shared_ptr<engineserver::EngineServer> server;

    try
    {
        const auto bufferSize {static_cast<size_t>(queueSize)};

        server = std::make_shared<engineserver::EngineServer>(
            apiEndpoint, nullptr, eventEndpoint, bufferSize);
        g_exitHanlder.add([server]() { server->close(); });

        WAZUH_LOG_INFO("Server configured");

        KVDBManager::init(kvdbPath);
        WAZUH_LOG_INFO("KVDB initialized");
        g_exitHanlder.add(
            []()
            {
                WAZUH_LOG_INFO("KVDB terminated");
                KVDBManager::get().clear();
            });

        store = std::make_shared<store::FileDriver>(fileStorage);
        WAZUH_LOG_INFO("Store initialized");

        builder = std::make_shared<builder::Builder>(store);
        WAZUH_LOG_INFO("Builder initialized");

        api::catalog::Config catalogConfig {store, builder};
        catalog = std::make_shared<api::catalog::Catalog>(catalogConfig);
        api::catalog::cmds::registerAllCmds(catalog, server->getRegistry());
        WAZUH_LOG_INFO("Catalog initialized");

        // server = std::make_shared<engineserver::EngineServer>(
        //     std::vector<std::string> {"api:"+apiEndpoint});
        auto hlpParsers = store->get({"schema.wazuh-logql-types.v0"});
        if (std::holds_alternative<base::Error>(hlpParsers))
        {
            WAZUH_LOG_ERROR("[HLP] Error retreiving schema.wazuh-logql-types.v0 "
                            "from store: {}",
                            std::get<base::Error>(hlpParsers).message);

            g_exitHanlder.execute();
            exit(1);
        }
        // TODO because builders don't have access to the catalog we are configuring
        // the parser mappings on start up for now
        hlp::configureParserMappings(std::get<json::Json>(hlpParsers).str());
        WAZUH_LOG_INFO("HLP initialized");

        builder::internals::registerBuilders();
        WAZUH_LOG_INFO("Builders registered");

    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Error initializing modules: {}", utils::getExceptionStack(e));
        g_exitHanlder.execute();
        exit(1);
    }

    // Set up environment
    try
    {
        WAZUH_LOG_INFO("Setting up environment [{}]...", environment);
        auto env = builder->buildEnvironment({environment});
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_WARN("Error building environment [{}]: {}",
                       environment,
                       utils::getExceptionStack(e));
        WAZUH_LOG_WARN("Engine running without environment");
    }

    // Start server
    try
    {
        server->run();
    }
    catch (const std::exception& e)
    {
        WAZUH_LOG_ERROR("Unexpected error: {}", utils::getExceptionStack(e));
        g_exitHanlder.execute();
        exit(1);
    }

    // engineserver::EngineServer server {
    //     {endpoint, "api:/var/ossec/queue/sockets/analysis"},
    //     static_cast<size_t>(queueSize)};
    // if (!server.isConfigured())
    // {
    //     WAZUH_LOG_ERROR("Could not configure server for endpoint [{}], engine "
    //                     "inizialization aborted.",
    //                     endpoint);
    //     destroy();
    //     return;
    // }

    // // Processing Workers (Router), Router is replicated in each thread
    // // TODO: handle hot modification of routes
    // for (auto i = 0; i < threads; ++i)
    // {
    //     std::thread t {
    //         [=, &eventBuffer = server.output()]()
    //         {
    //             // TODO: Handle errors on construction
    //             builder::Builder _builder(store);
    //             decltype(_builder.buildEnvironment(environment)) env;
    //             try
    //             {
    //                 env = _builder.buildEnvironment(environment);
    //             }
    //             catch (const std::exception& e)
    //             {
    //                 WAZUH_LOG_ERROR("Exception while building environment: [{}]",
    //                                 utils::getExceptionStack(e));
    //                 destroy();
    //                 return -1;
    //             }
    //             auto controller = rxbk::buildRxPipeline(env);

    //             // Thread loop
    //             while (gs_doRun)
    //             {
    //                 std::string event;

    //                 if (eventBuffer.wait_dequeue_timed(event,
    //                 WAIT_DEQUEUE_TIMEOUT_USEC))
    //                 {
    //                     try
    //                     {
    //                         auto result = base::result::makeSuccess(
    //                             engineserver::base::parseEvent::parseOssecEvent(event));
    //                         controller.ingestEvent(
    //                             std::make_shared<base::result::Result<base::Event>>(
    //                                 std::move(result)));
    //                     }
    //                     catch (const std::exception& e)
    //                     {
    //                         WAZUH_LOG_ERROR(
    //                             "An error ocurred while parsing a message: [{}]",
    //                             e.what());
    //                     }
    //                 }
    //             }

    //             controller.complete();
    //             return 0;
    //         }};

    //     gs_threadList.push_back(std::move(t));
    // }

    // server.run();
    g_exitHanlder.execute();
}
} // namespace cmd
