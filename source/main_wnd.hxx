#ifndef MAIN_WND_HXX
#define MAIN_WND_HXX

// Qt Library Includes.
#include <QMainWindow>

#include <QtConcurrent/QtConcurrent>
#include <QFutureWatcher>

// Standard Library Includes.
#include <functional>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <map>

// Miniature plotting widget for Qt.
#include <qcustomplot.h>

// LibCurl
#define CURL_STATICLIB
#include <curl/curl.h>
constexpr const bool VERBOSE_CURL = false;

// Nlohmann's JSON library for modern C++
#include <json.hpp>
using Json = nlohmann::json;

/* Helper function that converts a double into a string, but with
 * adjustable precision. Uses iomanip and stringstream. */
std::string to_string_precision(double value, uint32_t precision);

template<typename T>
class AsyncType {
protected:
    std::mutex typeMutex;
    T typeValue;

public:
    const std::mutex& TypeMutex = typeMutex;

    T Get() {
       std::lock_guard<std::mutex> lock_guard(typeMutex);
       T value_copy = typeValue;
       return value_copy;
    }

    void Set(T new_value) {
        std::lock_guard<std::mutex> lock_guard(typeMutex);
        typeValue = new_value;
    }

    explicit operator T() {
        return Get();
    }

    T operator=(T value) {
        std::lock_guard<std::mutex> lock_guard(typeMutex);
        typeValue = value;
        return value;
    }

    AsyncType(T initial_value) : typeValue(initial_value) {}
    AsyncType() {}
};

class RaiiExecution {
protected:
    std::function<void()> destructionLambda;

public:
    template<typename CLAMBDA, typename DLAMBDA>
    RaiiExecution(CLAMBDA construction_lambda, DLAMBDA destruction_lambda) {
        destructionLambda = destruction_lambda;
        construction_lambda();
    }

    ~RaiiExecution() {
        destructionLambda();
    }
};

namespace Http {
    struct Response {
        std::string Body;
        std::string Header;
        int16_t Code;
        bool Filled;
    };

    std::size_t CurlWriter(void* data, std::size_t fake_size, std::size_t size, std::string* out_string);

    Response Post(
        const std::string& url,
        const std::vector<std::pair<std::string, std::string>>& post_fields,
        const std::vector<std::pair<std::string, std::string>>& post_files,
        const std::pair<std::string, std::string>& http_authentication,
        uint32_t timeout = 0
    );

    Response Put(
        const std::string& url,
        const std::string& body,
        const std::pair<std::string, std::string>& http_authentication,
        uint32_t timeout = 0
    );

    Response Get(const std::string& url, const std::pair<std::string, std::string>& http_authentication, uint32_t timeout = 0);
}

namespace Ui {
    class MainWindow;
}

class MainWindow : public QMainWindow {
private: Q_OBJECT
    Ui::MainWindow* ui;

protected:
    // Struct to store the responses made by API calls, and the ascociated endpoint.
    struct EndpointData {
        std::string Endpoint;
        Http::Response Response;
    };

    // Struct to store the authorization Id/Key pair.
    struct AuthCredentials {
        std::string Id;
        std::string Key;

        operator std::pair<std::string, std::string>();
        operator std::pair<std::string, std::string>() const;

        bool ValidSize() const;
    };

/* ---------- Compile Time Constants ---- */

    static constexpr const char* ENDP_SYSTEM_INFO = "/api/v1/system";
    static constexpr const char* ENDP_NETWORK_INFO = "/api/v1/printer/network";

    static constexpr const char* ENDP_BED_TEMPERATURE = "/api/v1/printer/bed/temperature";
    static constexpr const char* ENDP_EXT1_TEMPERATURE = "/api/v1/printer/heads/0/extruders/0/hotend/temperature";
    static constexpr const char* ENDP_EXT2_TEMPERATURE = "/api/v1/printer/heads/0/extruders/1/hotend/temperature";

    static constexpr const char* ENDP_PRINTJOB_STATE = "/api/v1/print_job/state";
    static constexpr const char* ENDP_PRINT_HISTORY = "/api/v1/history/print_jobs";
    static constexpr const char* ENDP_PRINT_JOB = "/api/v1/print_job";

    static constexpr const char* ENDP_AUTH_VERIFICATION = "/api/v1/auth/verify";
    static constexpr const char* ENDP_AUTH_REQUEST = "/api/v1/auth/request";
    static constexpr const char* ENDP_AUTH_CHECK = "/api/v1/auth/check/";


/* ---------- Temperature Plots ---------- */

    // The plot widgets that will plot the bed and extruder temperatures.
    QCustomPlot* primaryExtruderPlot;
    QCustomPlot* secondaryExtruderPlot;
    QCustomPlot* printBedPlot;

    // Temperature values.
    QVector<double> printBedPlotData;
    QVector<double> primaryExtruderPlotData;
    QVector<double> secondaryExtruderPlotData;

    // Time frame values (0 - 100).
    QVector<double> printBedPlotFrames;
    QVector<double> primaryExtruderPlotFrames;
    QVector<double> secondaryExtruderPlotFrames;

/* ---------- Print History Widgets ---------- */

    // The group box and print history that will be inserted into the layout when togled.
    QGroupBox* printHistoryGroupBox;
    QListWidget* printHistory;

    // Stores whether or not the print history is inserted/expanded.
    bool printHistoryExpanded;

/* ---------- Request Variables ---------- */

    // The IPv4 address used to make API requests.
    AsyncType<std::string> printerIpv4Address;

    /* The id/key used for requests that require
     * HTTP authorization. */
    AsyncType<AuthCredentials> authCredentials;

/* ---------- Polling ---------- */

    /* True when an endpoint response is being handled and the corresponding
     * UI elements are being updated, false when not. */
    std::atomic<bool> handlingResponse;

/* The following futures, watchers, and timers are ascociated
 * with the poller and handler functions further below.
 * The futures store the polling response for a given
 * endpoint, and the watchers signal the handler for the
 * corresponding handler function which will update the UI.
 * The timers specify how frequently the polling functions
 * will be called. */
protected:
    QFutureWatcher<EndpointData>* printHistoryResponseWatcher;
    QFuture<EndpointData> printHistoryResponse;
    QTimer* printHistoryPollingTimer;

    QFutureWatcher<EndpointData>* printjobResponseWatcher;
    QFuture<EndpointData> printjobResponse;
    QTimer* printjobPollingTimer;

    QFutureWatcher<EndpointData>* systemInfoResponseWatcher;
    QFuture<EndpointData> systemInfoResponse;
    QTimer* systemInfoPollingTimer;

    QFutureWatcher<EndpointData>* temperatureResponseWatcher;
    QFuture<EndpointData> temperatureResponses;
    QTimer* temperaturePollingTimer;

    QFutureWatcher<Http::Response>* uploadFinishedResponseWatcher;
    QFuture<Http::Response> uploadFinishedResponse;

/* The following functions are polling and handling functions.
 * The polling functions concurrently poll data from the printer
 * API whenever the polling timer for that function times out.
 * The results are then stored in the above futures, and the
 * corresponding watcher will signal the handler for the polled
 * data, which will handle and update the UI with the new data. */
protected slots:
    void pollTemperature();
    void handleTemperatureResponses(int);

    void pollSystemInfo();
    void handleSystemInfoResponse();

    void pollPrintHistory();
    void handlePrintHistoryResponse();

    void pollPrintJob();
    void handlePrintJobResponse();

/* ---------- UI Element Interaction Slots ---------- */

protected slots:
    // Will request authorization from the printer, and if succfully verified, will store it within authorizationId & authorizationKey.
    void on_btn_request_auth_clicked();

    // Attempts to reach the printer who's IP address was typed into the textbox, if succesful, stores the IP into printerIpv4Address.
    void on_btn_connect_clicked();

    // Toggles the polling timers on and off.
    void on_btn_polling_clicked();

    // Expands the print history on the right side of the GUI.
    void on_tbt_expand_history_clicked();

    void on_btn_abort_clicked();

    void on_btn_pause_clicked();

    void on_btn_resume_clicked();

    /* Prompts a file selection, and then starts a concurrent upload of the selected GCode file to the printer.
     * Once the upload is complete, the upload finished handler is called. */
    void on_btn_upload_clicked();
    void uploadFinishedHandler();

public:
    explicit MainWindow(QWidget* parent = nullptr);
    virtual ~MainWindow();
};

#endif // MAIN_WND_HXX