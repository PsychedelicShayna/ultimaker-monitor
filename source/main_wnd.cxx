#include "main_wnd.hxx"
#include "ui_main_wnd.h"

std::string to_string_precision(double value, uint32_t precision) {
    std::stringstream conversion_stream;
    conversion_stream << std::fixed << std::setprecision(precision) << value;
    return conversion_stream.str();
}

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Http Namespace Definitions


std::size_t Http::CurlWriter(void* data, std::size_t fake_size, std::size_t size, std::string* out_string) {
    out_string->append(reinterpret_cast<char*>(data), fake_size * size);
    return fake_size * size;
}

Http::Response Http::Post(
    const std::string& url,
    const std::vector<std::pair<std::string, std::string>>& post_fields,
    const std::vector<std::pair<std::string, std::string>>& post_files,
    const std::pair<std::string, std::string>& http_authentication,
    uint32_t timeout
){
    CURL* curl_session = curl_easy_init();

    Http::Response http_response;

    if(curl_session) {
        curl_easy_setopt(curl_session, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl_session, CURLOPT_USERAGENT, "curl");
        curl_easy_setopt(curl_session, CURLOPT_TCP_KEEPALIVE, 2);
        curl_easy_setopt(curl_session, CURLOPT_VERBOSE, VERBOSE_CURL);

        curl_easy_setopt(curl_session, CURLOPT_POST, true);

        curl_easy_setopt(curl_session, CURLOPT_WRITEFUNCTION, &Http::CurlWriter);
        curl_easy_setopt(curl_session, CURLOPT_WRITEDATA, &http_response.Body);
        curl_easy_setopt(curl_session, CURLOPT_HEADERDATA, &http_response.Header);

        curl_easy_setopt(curl_session, CURLOPT_CONNECTTIMEOUT, timeout);


        struct curl_httppost* form_data = nullptr;
        struct curl_httppost* last_form_data = nullptr;
        std::string post_fields_string;

        if(http_authentication.first.size() || http_authentication.second.size()) {
            curl_easy_setopt(curl_session, CURLOPT_HTTPAUTH, CURLAUTH_ANY);

            if(http_authentication.first.size()) {
                curl_easy_setopt(curl_session, CURLOPT_USERNAME, http_authentication.first.c_str());
            }

            if(http_authentication.second.size()) {
                curl_easy_setopt(curl_session, CURLOPT_PASSWORD, http_authentication.second.c_str());
            }
        }

        if(post_fields.size()) {
            std::stringstream post_fields_stream;

            for(const auto& post_field : post_fields) {
                post_fields_stream.seekg(0, std::ios::end);
                std::size_t stream_size = post_fields_stream.tellg();
                post_fields_stream.seekg(0, std::ios::beg);

                post_fields_stream <<
                    (stream_size > 0 ? "&" + post_field.first : post_field.first) << (post_field.second.size() ? "=" + post_field.second : "");
            }

            post_fields_string = post_fields_stream.str();
            curl_easy_setopt(curl_session, CURLOPT_POSTFIELDS, post_fields_string.c_str());
        }

        if(post_files.size()) {
            for(const auto& post_file : post_files) {
                curl_formadd(&form_data, &last_form_data, CURLFORM_COPYNAME, post_file.first.c_str(), CURLFORM_FILE, post_file.second.c_str(), CURLFORM_END);
            }

            curl_easy_setopt(curl_session, CURLOPT_HTTPPOST, form_data);
        }

        curl_easy_perform(curl_session);
        curl_easy_getinfo(curl_session, CURLINFO_HTTP_CODE, &http_response.Code);
        http_response.Filled = true;

        curl_easy_cleanup(curl_session);
        curl_session = nullptr;
    }

    return http_response;
}

Http::Response Http::Put(const std::string& url, const std::string& body, const std::pair<std::string, std::string>& http_authentication, uint32_t timeout) {
    CURL* curl_session = curl_easy_init();

    Http::Response http_response;

    if(curl_session) {
        struct curl_slist* headers = NULL;

        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl_session, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl_session, CURLOPT_URL, url.c_str());

        curl_easy_setopt(curl_session, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(curl_session, CURLOPT_USERAGENT, "curl");
        curl_easy_setopt(curl_session, CURLOPT_POSTFIELDS, body.c_str());

        curl_easy_setopt(curl_session, CURLOPT_WRITEFUNCTION, &Http::CurlWriter);
        curl_easy_setopt(curl_session, CURLOPT_WRITEDATA, &http_response.Body);
        curl_easy_setopt(curl_session, CURLOPT_HEADERDATA, &http_response.Header);
        curl_easy_setopt(curl_session, CURLOPT_CONNECTTIMEOUT, timeout);

        curl_easy_setopt(curl_session, CURLOPT_VERBOSE, VERBOSE_CURL);

        if(http_authentication.first.size() || http_authentication.second.size()) {
            curl_easy_setopt(curl_session, CURLOPT_HTTPAUTH, CURLAUTH_ANY);

            if(http_authentication.first.size()) {
                curl_easy_setopt(curl_session, CURLOPT_USERNAME, http_authentication.first.c_str());
            }

            if(http_authentication.second.size()) {
                curl_easy_setopt(curl_session, CURLOPT_PASSWORD, http_authentication.second.c_str());
            }
        }

        curl_easy_perform(curl_session);

        curl_easy_getinfo(curl_session, CURLINFO_HTTP_CODE, &http_response.Code);

        http_response.Filled = true;

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl_session);
        curl_session = nullptr;
    }

    return http_response;
}

Http::Response Http::Get(const std::string& url, const std::pair<std::string, std::string>& http_authentication, uint32_t timeout) {
    CURL* curl_session = curl_easy_init();

    Http::Response http_response;

    if(curl_session) {
        curl_easy_setopt(curl_session, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl_session, CURLOPT_USERAGENT, "curl");
        curl_easy_setopt(curl_session, CURLOPT_HTTPGET, 1L);
        curl_easy_setopt(curl_session, CURLOPT_WRITEFUNCTION, &Http::CurlWriter);
        curl_easy_setopt(curl_session, CURLOPT_WRITEDATA, &http_response.Body);
        curl_easy_setopt(curl_session, CURLOPT_HEADERDATA, &http_response.Header);
        curl_easy_setopt(curl_session, CURLOPT_TCP_KEEPALIVE, 2UL);
        curl_easy_setopt(curl_session, CURLOPT_VERBOSE, VERBOSE_CURL);
        curl_easy_setopt(curl_session, CURLOPT_CONNECTTIMEOUT, timeout);

        if(http_authentication.first.size() || http_authentication.second.size()) {
            curl_easy_setopt(curl_session, CURLOPT_HTTPAUTH, CURLAUTH_ANY);

            if(http_authentication.first.size()) {
                curl_easy_setopt(curl_session, CURLOPT_USERNAME, http_authentication.first.c_str());
            }

            if(http_authentication.second.size()) {
                curl_easy_setopt(curl_session, CURLOPT_PASSWORD, http_authentication.second.c_str());
            }
        }

        curl_easy_perform(curl_session);

        curl_easy_getinfo(curl_session, CURLINFO_HTTP_CODE, &http_response.Code);
        http_response.Filled = true;

        curl_easy_cleanup(curl_session);
        curl_session = nullptr;
    }

    return http_response;
}

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// MainWindow Class Definitions


/* ---------- Temperature Polling / Handling ---------- */
void MainWindow::pollTemperature() {
    if((temperatureResponseWatcher->isFinished() || !(temperatureResponseWatcher->isStarted())) && !handlingResponse) {
        QList<EndpointData> temperature_endpoints {
            {ENDP_BED_TEMPERATURE,      Http::Response()},
            {ENDP_EXT1_TEMPERATURE,     Http::Response()},
            {ENDP_EXT2_TEMPERATURE,     Http::Response()}
        };

        std::function<EndpointData(EndpointData)> request_function = [this](EndpointData temperature_endpoint) -> EndpointData {
            temperature_endpoint.Response = Http::Get(printerIpv4Address.Get() + temperature_endpoint.Endpoint, {});
            return temperature_endpoint;
        };

        temperatureResponses = QtConcurrent::mapped(temperature_endpoints, request_function);
        temperatureResponseWatcher->setFuture(temperatureResponses);
    }
}
void MainWindow::handleTemperatureResponses(int response_index) {
    AtomicDestructionGuard<bool> atomic_destruction_guard(&handlingResponse, false);
    handlingResponse = true;

    const EndpointData& response_data = temperatureResponses.resultAt(response_index);
    const std::string& response_endpoint = response_data.Endpoint;
    const Http::Response& response = response_data.Response;

    Json response_json;

    if(response.Filled) {
        try {
            response_json = Json::parse(response.Body);
        } catch(const nlohmann::detail::exception& json_exception) {
            std::cerr << "JSON Exception (" << json_exception.what() << ") when parsing response from endpoint " <<
                response_endpoint << " - code " << response.Code << std::endl;

            return;
        }
    } else {
        std::cerr << "Response from endpoint " << response_endpoint << " wans't filled." << std::endl;
        return;
    }

    if(response_endpoint == ENDP_BED_TEMPERATURE && response.Code == 200) {
        const double current_temperature = response_json.at("current").get<double>();
        const double target_temperature = response_json.at("target").get<double>();

        ui->rbt_heater_active->setChecked(target_temperature > 0);

        if(target_temperature >= current_temperature) {
            ui->prg_thermal_target->setRange(0, static_cast<int32_t>(std::round(target_temperature)));
            ui->prg_thermal_target->setValue(static_cast<int32_t>(std::round(current_temperature)));
            ui->prg_thermal_target->setFormat("THERMAL TARGET %p% (%v °C / %m °C)");
            ui->prg_thermal_target->setEnabled(true);
        } else {
            ui->prg_thermal_target->setRange(0, 1);
            ui->prg_thermal_target->setValue(1);
            ui->prg_thermal_target->setFormat("THERMAL TARGET %p% (" + QString(QString::number(current_temperature) + " °C / 0 °C)"));
            ui->prg_thermal_target->setEnabled(false);
        }

        printBedPlotData.removeFirst();
        printBedPlotData.append(current_temperature);
        printBedPlot->graph(0)->setData(printBedPlotFrames, printBedPlotData);
        printBedPlot->replot();
    } else if(response_endpoint == ENDP_EXT1_TEMPERATURE) {
        const double current_temperature = response_json.at("current").get<double>();
        const double target_temperature = response_json.at("target").get<double>();

        ui->rbt_ext1_heater_active->setChecked(target_temperature > 0);

        if(target_temperature >= current_temperature) {
            ui->prg_ext1_thermal_target->setRange(0, static_cast<int32_t>(std::round(target_temperature)));
            ui->prg_ext1_thermal_target->setValue(static_cast<int32_t>(std::round(current_temperature)));
            ui->prg_ext1_thermal_target->setFormat("THERMAL TARGET %p% (%v °C / %m °C)");
            ui->prg_ext1_thermal_target->setEnabled(true);
        } else {
            ui->prg_ext1_thermal_target->setRange(0, 1);
            ui->prg_ext1_thermal_target->setValue(1);
            ui->prg_ext1_thermal_target->setFormat("THERMAL TARGET %p% (" + QString(QString::number(current_temperature) + " °C / 0 °C)"));
            ui->prg_ext1_thermal_target->setEnabled(false);
        }

        primaryExtruderPlotData.removeFirst();
        primaryExtruderPlotData.append(current_temperature);
        primaryExtruderPlot->graph(0)->setData(primaryExtruderPlotFrames, primaryExtruderPlotData);
        primaryExtruderPlot->replot();

    } else if(response_endpoint == ENDP_EXT2_TEMPERATURE) {
        const double current_temperature = response_json.at("current").get<double>();
        const double target_temperature = response_json.at("target").get<double>();

        ui->rbt_ext2_heater_active->setChecked(target_temperature > 0);

        if(target_temperature >= current_temperature) {
            ui->prg_ext2_thermal_target->setRange(0, static_cast<int32_t>(std::round(target_temperature)));
            ui->prg_ext2_thermal_target->setValue(static_cast<int32_t>(std::round(current_temperature)));
            ui->prg_ext2_thermal_target->setFormat("THERMAL TARGET %p% (%v °C / %m °C)");
            ui->prg_ext2_thermal_target->setEnabled(true);
        } else {
            ui->prg_ext2_thermal_target->setRange(0, 1);
            ui->prg_ext2_thermal_target->setValue(1);
            ui->prg_ext2_thermal_target->setFormat("THERMAL TARGET %p% (" + QString(QString::number(current_temperature) + " °C / 0 °C)"));
            ui->prg_ext2_thermal_target->setEnabled(false);
        }

        secondaryExtruderPlotData.removeFirst();
        secondaryExtruderPlotData.append(current_temperature);
        secondaryExtruderPlot->graph(0)->setData(secondaryExtruderPlotFrames, secondaryExtruderPlotData);
        secondaryExtruderPlot->replot();
    }
}


/* ---------- Printjob Polling / Handling ---------- */
void MainWindow::pollPrintJob() {
    if((printjobResponseWatcher->isFinished() || !(printjobResponseWatcher->isStarted())) && !handlingResponse) {
        printjobResponse = QtConcurrent::run([this](EndpointData printjob_endpoint) -> EndpointData {
            printjob_endpoint.Response = Http::Get(printerIpv4Address.Get() + printjob_endpoint.Endpoint, {});
            return printjob_endpoint;
        }, EndpointData {ENDP_PRINT_JOB, Http::Response()});

        printjobResponseWatcher->setFuture(printjobResponse);
    }
}
void MainWindow::handlePrintJobResponse() {
    AtomicDestructionGuard<bool> atomic_destruction_guard(&handlingResponse, false);
    handlingResponse = true;

    const EndpointData& response_data = printjobResponse.result();
    const std::string& response_endpoint = response_data.Endpoint;
    const Http::Response& response = response_data.Response;

    Json response_json;

    if(response.Filled) {
        try {
            response_json = Json::parse(response.Body);
        } catch(const nlohmann::detail::exception& json_exception) {
            std::cerr << "JSON Exception (" << json_exception.what() << ") when parsing response from endpoint " <<
                response_endpoint << " - code " << response.Code << std::endl;

            return;
        }
    } else {
        std::cerr << "Response from endpoint " << response_endpoint << " wans't filled." << std::endl;
        return;
    }

    if(response.Code == 200 || response.Code == 201) {
        ui->grp_printjob->setTitle(QString::fromStdString("PRINT JOB - " + response_json.at("name").get<std::string>()));

        const double& time_elapsed = response_json.at("time_elapsed").get<double>();
        const double& time_total = response_json.at("time_total").get<double>();

        if(time_elapsed <= time_total) {
            ui->prg_printjob->setRange(0, static_cast<int32_t>(std::round(time_total)));
            ui->prg_printjob->setValue(static_cast<int32_t>(std::round(time_elapsed)));
        } else {
            ui->prg_printjob->setRange(0, 1);
            ui->prg_printjob->setValue(1);
        }

        std::string time_elapsed_str, time_total_str;

        if(time_elapsed < 60) {
            time_elapsed_str = to_string_precision(time_elapsed, 2) + " Seconds";
        } else if((time_elapsed / 60) < 60) {
            time_elapsed_str = to_string_precision(time_elapsed / 60, 2) + " Minutes";
        } else {
            time_elapsed_str = to_string_precision(time_elapsed / 60 / 60, 2) + " Hours";
        }

        if(time_total < 60) {
            time_total_str = to_string_precision(time_total, 2) + " Seconds";
        } else if((time_elapsed / 60) < 60) {
            time_total_str = to_string_precision(time_total / 60, 2) + " Minutes";
        } else {
            time_total_str = to_string_precision(time_total / 60 / 60, 2) + " Hours";
        }

        ui->prg_printjob->setFormat("%p% (" + QString::fromStdString(time_elapsed_str) + " / " + QString::fromStdString(time_total_str) + ")");
    } else if(response.Code == 404) {
        ui->grp_printjob->setTitle("PRINT JOB");
        ui->prg_printjob->setFormat("NO PRINT JOB");
        ui->prg_printjob->setRange(0, 1);
        ui->prg_printjob->setValue(0);
    }
}


/* ---------- System Information Polling / Handling ---------- */
void MainWindow::pollSystemInfo() {
    if((systemInfoResponseWatcher->isFinished() || !(systemInfoResponseWatcher->isStarted())) && !handlingResponse) {
        systemInfoResponse = QtConcurrent::run([this](EndpointData sysinfo_endpoint) -> EndpointData {
            sysinfo_endpoint.Response = Http::Get(printerIpv4Address.Get() + sysinfo_endpoint.Endpoint, {});
            return sysinfo_endpoint;
        }, EndpointData {ENDP_SYSTEM_INFO, Http::Response()});

        systemInfoResponseWatcher->setFuture(systemInfoResponse);

    }
}
void MainWindow::handleSystemInfoResponse() {
    AtomicDestructionGuard<bool> atomic_destruction_guard(&handlingResponse, false);
    handlingResponse = true;

    const EndpointData& response_data = systemInfoResponse.result();
    const std::string& response_endpoint = response_data.Endpoint;
    const Http::Response& response = response_data.Response;

    Json response_json;

    if(response.Filled) {
        try {
            response_json = Json::parse(response.Body);
        } catch(const nlohmann::detail::exception& json_exception) {
            std::cerr << "JSON Exception (" << json_exception.what() << ") when parsing response from endpoint " <<
                response_endpoint << " - code " << response.Code << std::endl;

            return;
        }
    } else {
        std::cerr << "Response from endpoint " << response_endpoint << " wans't filled." << std::endl;
        return;
    }

    if(response.Code == 200) {
        ui->pte_syslog->clear();

        const double& system_uptime = response_json.at("uptime").get<double>() / 60 / 60 / 24;
        ui->lcd_uptime->display(system_uptime);

        const std::vector<std::string>& log_messages = response_json.at("log").get<std::vector<std::string>>();
        QVector<QString> q_log_messages(static_cast<int32_t>(log_messages.size()));

        std::transform(log_messages.begin(), log_messages.end(), q_log_messages.begin(), [](const std::string& log_message) -> QString {
            return QString::fromStdString(log_message);
        });

        for(const auto& log_message : q_log_messages) {
            ui->pte_syslog->appendPlainText(log_message);
        }

        const auto& memory = response_json.at("memory");

        uint32_t memory_capacity = memory.at("total").get<uint32_t>();
        uint32_t memory_usage = memory.at("used").get<uint32_t>();

        memory_capacity = static_cast<uint32_t>(std::round(static_cast<double>(memory_capacity) / 1024 / 1024));
        memory_usage = static_cast<uint32_t>(std::round(static_cast<double>(memory_usage) / 1024 / 1024));

        ui->prg_memory->setRange(0, memory_capacity);
        ui->prg_memory->setValue(memory_usage);
    }
}


/* ---------- Print History Polling / Handling ---------- */
void MainWindow::pollPrintHistory(){
    if((printHistoryResponseWatcher->isFinished() || !(printHistoryResponseWatcher->isStarted())) && !handlingResponse) {
        printHistoryResponse = QtConcurrent::run([this](EndpointData printhistory_endpoint) -> EndpointData {
            printhistory_endpoint.Response = Http::Get(printerIpv4Address.Get() + printhistory_endpoint.Endpoint, {});
            return printhistory_endpoint;
        }, EndpointData {ENDP_PRINT_HISTORY, Http::Response()});

        printHistoryResponseWatcher->setFuture(printHistoryResponse);
    }
}
void MainWindow::handlePrintHistoryResponse() {
    AtomicDestructionGuard<bool> atomic_destruction_guard(&handlingResponse, false);
    handlingResponse = true;

    const EndpointData& response_data = printHistoryResponse.result();
    const std::string& response_endpoint = response_data.Endpoint;
    const Http::Response& response = response_data.Response;

    Json response_json;

    if(response.Filled) {
        try {
            response_json = Json::parse(response.Body);
        } catch(const nlohmann::detail::exception& json_exception) {
            std::cerr << "JSON Exception (" << json_exception.what() << ") when parsing response from endpoint " <<
                response_endpoint << " - code " << response.Code << std::endl;

            return;
        }
    } else {
        std::cerr << "Response from endpoint " << response_endpoint << " wans't filled." << std::endl;
        return;
    }

    if(response.Code == 200) {
        printHistory->clear();

        for(const auto& print_job : response_json) {
            const std::string& time_finished = print_job.at("datetime_finished").get<std::string>();
            const std::string& time_started = print_job.at("datetime_started").get<std::string>();
            const std::string& source = print_job.at("source").get<std::string>();
            const std::string& result = print_job.at("result").get<std::string>();
            const std::string& name = print_job.at("name").get<std::string>();

            printHistory->addItem(QString::fromStdString(time_started + " - " + time_finished + " | " + name + " (" + source + ") = " + result));
        }
    }
}


/* ---------- Printjob Uploading / Response Handling ---------- */
void MainWindow::on_btn_upload_clicked() {
    if(!(authorizationId.size() && authorizationKey.size())) {
        QMessageBox::warning(this, "Authorization Problem", "Cannot upload a printjob without credentials, request credentials.");
        return;
    }

    const std::string& printer_ipv4_address = printerIpv4Address.Get();

    if(!printer_ipv4_address.size()) {
        QMessageBox::warning(this, "Connection Problem", "Not connected to any printer.");
        return;
    }

    const std::string& file_name = QFileDialog::getOpenFileName(this, "Select Spliced GCode", ".", "GCode Files (*.gcode)").toStdString();

    std::ifstream file_stream(file_name, std::ios::binary);

    if(!file_stream.good()) {
        QMessageBox::warning(this, "I/O Error", "Couldn't open the selected GCode file for reading, ensure you have the correct privilages.");
        return;
    } else {
        file_stream.close();
    }

    ui->btn_upload->setText("Uploading..");

    uploadFinishedResponse = QtConcurrent::run([this](const std::string printer_ipv4_address, const std::string file_name) -> Http::Response {
        Http::Response response = Http::Post(
             "http://" + printer_ipv4_address + "/api/v1/print_job",
             {{"jobname", file_name}},
             {{"file", file_name}},
             {authorizationId, authorizationKey}
        );

        return response;
    }, printer_ipv4_address, file_name);

    uploadFinishedResponseWatcher->setFuture(uploadFinishedResponse);
}
void MainWindow::uploadFinishedHandler() {
    ui->btn_upload->setText("Upload Job To Printer");

    Http::Response printer_response = uploadFinishedResponse.result();

    if(printer_response.Filled) {
        switch(printer_response.Code) {
            case 200 : break;
            case 201 : break;

            case 401 : {
                QMessageBox::warning(this, "Code 401", "Authorization required.");
                break;
            }

            case 403 : {
                QMessageBox::warning(this, "Code 403", "Authorization denied.");
                break;
            }

            case 405 : {
                QMessageBox::warning(this, "Code 405", "Cannot currently upload a printjob.");
                break;
            }

            default : {
                QMessageBox::warning(this, "Unhandled Code", "Unhandled HTTP response code: " + QString::number(printer_response.Code));
                break;
            }
        }
    } else {
        QMessageBox::warning(this, "Timeout", "No response was given from the printer.");
    }
}

/* ---------- Various UI Element Slots ---------- */
void MainWindow::on_btn_request_auth_clicked() {
    ui->btn_request_auth->setText("Requesting..");

    std::string printer_ipv4_address = printerIpv4Address.Get();

    Http::Response authorization_response = Http::Post(
        "http://" + printer_ipv4_address + "/api/v1/auth/request",
        {{"application", "Ultimaker-Monitor"}, {"user", "Ultimaker-Monitor"}},
        {},
        {}
    );

    if(authorization_response.Filled && authorization_response.Code == 200) {
        QMessageBox::information(this, "Authorization requested", "Printer authorization ahs been requested, confirm on the printer.");

        Json response_json = Json::parse(authorization_response.Body);

        std::string new_auth_key = response_json.at("key").get<std::string>();
        std::string new_auth_id = response_json.at("id").get<std::string>();

        bool verified = false;

        for(uint32_t i=0; i<10; ++i) {
            Http::Response verification_response = Http::Get(printer_ipv4_address + ENDP_AUTH_VERIFICATION, {new_auth_id, new_auth_key});

            if(verification_response.Filled && verification_response.Code == 200) {
                verified = true;
                break;
            } else {
                Sleep(1000);
            }
        }

        if(!verified) {
             QMessageBox::warning(this, "Authorization problem!", "The authorization received from the printer wasn't accepted in time.");
        } else {
            QMessageBox::information(this, "Authorization Successful", "The authorization recieved from the printer has been verified.");

            authorizationKey = new_auth_key;
            authorizationId = new_auth_id;

            std::ofstream credentials_file_stream("./printer-credentials.json", std::ios::binary);

            if(credentials_file_stream.good()) {
                const Json& credentials_json = {{"id", new_auth_id}, {"key", new_auth_key}};
                const std::string& credentials_string = credentials_json.dump();
                credentials_file_stream.write(credentials_string.data(), credentials_string.size());
                credentials_file_stream.close();
            }
        }

    } else {
        QMessageBox::warning(this, "Authorization problem!", "There was a problem requesting authorization from the printer. The response was bad.");
    }

    ui->btn_request_auth->setText("Request Authorization");

    std::cout << "Loaded Key/Id: " << authorizationKey << ":" << authorizationId << std::endl;
}
void MainWindow::on_btn_connect_clicked() {
    QString new_ipv4_address = ui->lin_address->text();

    ui->btn_connect->setText("Connecting..");

    Http::Response network_check_response = Http::Get(new_ipv4_address.toStdString() + "/api/v1/printer/network", {}, 2UL);

    if(network_check_response.Filled && network_check_response.Code == 200) {
        printerIpv4Address = new_ipv4_address.toStdString();
        ui->grp_system->setTitle("SYSTEM - " + new_ipv4_address);

        if(authorizationId.size() && authorizationKey.size()) {
            const std::string& verification_request_url  = new_ipv4_address.toStdString() + ENDP_AUTH_VERIFICATION;
            const Http::Response& verification_response = Http::Get(verification_request_url, {authorizationId, authorizationKey});

            if(!(verification_response.Filled && verification_response.Code == 200)) {
                authorizationId = "";
                authorizationKey = "";

                QMessageBox::warning(this, "Authorization problem!",
                    "The credentials stored in memory weren't validated by the printer. Credentials have been reset, request new credentials.");
            } else {
                QMessageBox::information(this, "Credentials Verified", "Pre-existing credentials have been verified for this new printer.");
            }
        }
    } else {
        QMessageBox::warning(this, "Cannot connect", "Couldn't connect to the printer with the specified IPv4 address.");
    }

    ui->btn_connect->setText("Connect");
}
void MainWindow::on_btn_polling_clicked() {
    if(ui->btn_polling->text() == "Start Polling") {
        /* These are manually called to ensure initial results
         * when polling is enabled, as their polling timers
         * take a long time to timeout. */
        pollPrintHistory();
        pollPrintJob();
        pollSystemInfo();

        printHistoryPollingTimer->start(10000);
        printjobPollingTimer->start(1000);
        systemInfoPollingTimer->start(7000);
        temperaturePollingTimer->start(500);

        ui->btn_polling->setText("Stop Polling");
    } else if(ui->btn_polling->text() == "Stop Polling") {
        printHistoryPollingTimer->stop();
        printjobPollingTimer->stop();
        systemInfoPollingTimer->stop();
        temperaturePollingTimer->stop();

        ui->btn_polling->setText("Start Polling");
    }
}
void MainWindow::on_tbt_expand_history_clicked() {
    if(printHistoryExpanded) {
        ui->vlo_print_history->removeWidget(printHistoryGroupBox);
        ui->hlo_master->setStretch(2, 0);
        printHistoryExpanded = false;
        printHistoryGroupBox->setVisible(false);
        ui->tbt_expand_history->setArrowType(Qt::ArrowType::RightArrow);
    } else {
        ui->vlo_print_history->addWidget(printHistoryGroupBox);
        ui->hlo_master->setStretch(2, 5);
        ui->tbt_expand_history->setArrowType(Qt::ArrowType::LeftArrow);
        printHistoryExpanded = true;
        printHistoryGroupBox->setVisible(true);
    }
}
void MainWindow::on_btn_abort_clicked() {
    if(!(authorizationId.size() && authorizationKey.size())) {
        QMessageBox::warning(this, "Authorization Problem", "Cannot change print state without credentials, request credentials.");
        return;
    }

    const std::string& printer_ipv4_address = printerIpv4Address.Get();

    if(!printer_ipv4_address.size()) {
        QMessageBox::warning(this, "Connection Problem", "Not connected to any printer.");
        return;
    }

    const std::string& request_url = printer_ipv4_address + ENDP_PRINTJOB_STATE;
    Http::Response abort_response = Http::Put(request_url, Json({{"target", "abort"}}).dump(), {authorizationId, authorizationKey});

    if(abort_response.Filled) {
        switch(abort_response.Code) {
            case 204 : break;
            case 201 : break;

            case 401 : {
                QMessageBox::warning(this, "Code 401", "Authorization required.");
                break;
            }

            case 403 : {
                QMessageBox::warning(this, "Code 403", "Authorization denied.");
                break;
            }

            case 404 : {
                QMessageBox::warning(this, "Code 404", "No printjob to change the state of.");
                break;
            }

            default : {
                QMessageBox::warning(this, "Unhandled Code", "Unhandled HTTP response code: " + QString::number(abort_response.Code));
                break;
            }
        }
    } else {
        QMessageBox::warning(this, "Timeout", "No response was given from the printer.");
    }
}
void MainWindow::on_btn_pause_clicked() {
    if(!(authorizationId.size() && authorizationKey.size())) {
        QMessageBox::warning(this, "Authorization Problem", "Cannot change print state without credentials, request credentials.");
        return;
    }

    const std::string& printer_ipv4_address = printerIpv4Address.Get();

    if(!printer_ipv4_address.size()) {
        QMessageBox::warning(this, "Connection Problem", "Not connected to any printer.");
        return;
    }

    const std::string& request_url = printer_ipv4_address + ENDP_PRINTJOB_STATE;
    Http::Response pause_response = Http::Put(request_url, Json({{"target", "pause"}}).dump(), {authorizationId, authorizationKey});

    if(pause_response.Filled) {
        switch(pause_response.Code) {
            case 204 : break;
            case 201 : break;

            case 401 : {
                QMessageBox::warning(this, "Code 401", "Authorization required.");
                break;
            }

            case 403 : {
                QMessageBox::warning(this, "Code 403", "Authorization denied.");
                break;
            }

            case 404 : {
                QMessageBox::warning(this, "Code 404", "No printjob to change the state of.");
                break;
            }

            default : {
                QMessageBox::warning(this, "Unhandled Code", "Unhandled HTTP response code: " + QString::number(pause_response.Code));
                break;
            }
        }
    } else {
        QMessageBox::warning(this, "Timeout", "No response was given from the printer.");
    }
}
void MainWindow::on_btn_resume_clicked() {
    if(!(authorizationId.size() && authorizationKey.size())) {
        QMessageBox::warning(this, "Authorization Problem", "Cannot change print state without credentials, request credentials.");
        return;
    }

    const std::string& printer_ipv4_address = printerIpv4Address.Get();

    if(!printer_ipv4_address.size()) {
        QMessageBox::warning(this, "Connection Problem", "Not connected to any printer.");
        return;
    }

    const std::string& request_url = printer_ipv4_address + ENDP_PRINTJOB_STATE;
    Http::Response resume_response = Http::Put(request_url, Json({{"target", "print"}}).dump(), {authorizationId, authorizationKey});

    if(resume_response.Filled) {
        switch(resume_response.Code) {
            case 204 : break;
            case 201 : break;

            case 401 : {
                QMessageBox::warning(this, "Code 401", "Authorization required.");
                break;
            }

            case 403 : {
                QMessageBox::warning(this, "Code 403", "Authorization denied.");
                break;
            }

            case 404 : {
                QMessageBox::warning(this, "Code 404", "No printjob to change the state of.");
                break;
            }

            default : {
                QMessageBox::warning(this, "Unhandled Code", "Unhandled HTTP response code: " + QString::number(resume_response.Code));
                break;
            }
        }
    } else {
        QMessageBox::warning(this, "Timeout", "No response was given from the printer.");
    }
}

/* ---------- Constructor & Destructor ---------- */
MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    /* ---------- Default Variable Values ---------- */
    {
        authorizationId = "";
        authorizationKey = "";

        handlingResponse = false;
        printHistoryExpanded = false;
    }

    /* ---------- Print History Polling Setup ---------- */
    {
        printHistoryResponseWatcher = new QFutureWatcher<EndpointData>(this);
        printHistoryPollingTimer = new QTimer(this);
        connect(printHistoryResponseWatcher, SIGNAL(finished()), this, SLOT(handlePrintHistoryResponse()));
        connect(printHistoryPollingTimer, SIGNAL(timeout()), this, SLOT(pollPrintHistory()));
    }

    /* ---------- Print Job Polling Setup ---------- */
    {
        printjobResponseWatcher = new QFutureWatcher<EndpointData>(this);
        printjobPollingTimer = new QTimer(this);
        connect(printjobResponseWatcher, SIGNAL(finished()), this, SLOT(handlePrintJobResponse()));
        connect(printjobPollingTimer, SIGNAL(timeout()), this, SLOT(pollPrintJob()));
    }

    /* ---------- System Info Polling Setup ---------- */
    {
        systemInfoResponseWatcher = new QFutureWatcher<EndpointData>(this);
        systemInfoPollingTimer = new QTimer(this);
        connect(systemInfoResponseWatcher, SIGNAL(finished()), this, SLOT(handleSystemInfoResponse()));
        connect(systemInfoPollingTimer, SIGNAL(timeout()), this, SLOT(pollSystemInfo()));
    }

    /* ---------- Temperature Polling Setup ---------- */
    {
        temperatureResponseWatcher = new QFutureWatcher<EndpointData>(this);
        temperaturePollingTimer = new QTimer(this);
        connect(temperatureResponseWatcher, SIGNAL(resultReadyAt(int)), this, SLOT(handleTemperatureResponses(int)));
        connect(temperaturePollingTimer, SIGNAL(timeout()), this, SLOT(pollTemperature()));
    }

    /* ---------- Printjob Upload Handler Setup ---------- */
    {
        uploadFinishedResponseWatcher = new QFutureWatcher<Http::Response>(this);
        connect(uploadFinishedResponseWatcher, SIGNAL(finished()), this, SLOT(uploadFinishedHandler()));
    }

    /* ---------- Print History List Widget Setup ---------- */
    {
        // Initialize the print history, and print history's group box.
        printHistoryGroupBox = new QGroupBox(this);
        printHistory = new QListWidget(printHistoryGroupBox);

        // Set the default properties for the print history's group box.
        printHistoryGroupBox->setTitle("PRINT HISTORY");
        printHistoryGroupBox->setVisible(false);

        /* Create a grid layout containing the print history, which the
         * print history's group box will implement. */
        QGridLayout* print_history_group_box_layout = new QGridLayout(this);
        print_history_group_box_layout->addWidget(printHistory);
        printHistoryGroupBox->setLayout(print_history_group_box_layout);
    }

    /* ---------- Stylesheet File Parsing ---------- */
    {
        std::ifstream stylesheet_stream("./amoled-green.qss", std::ios::binary);

        if(stylesheet_stream.good()) {
            std::vector<uint8_t> file_bytes(
                (std::istreambuf_iterator<char>(stylesheet_stream)),
                (std::istreambuf_iterator<char>())
            );

            stylesheet_stream.close();

            std::string stylesheet(file_bytes.begin(), file_bytes.end());
            setStyleSheet(QString::fromStdString(stylesheet));
        }
    }

    /* ---------- Credential File Parsing ---------- */
    {
        std::ifstream credentials_stream("./printer-credentials.json", std::ios::binary);

        if(credentials_stream.good()) {
            const std::vector<uint8_t> file_bytes(
                (std::istreambuf_iterator<char>(credentials_stream)),
                (std::istreambuf_iterator<char>())
            );

            credentials_stream.close();

            const std::string& credentials_string = std::string(file_bytes.begin(), file_bytes.end());

            try {
                const Json& credentials_json = Json::parse(credentials_string);

                if(credentials_json.contains("id") && credentials_json.contains("key") && credentials_json.at("id").is_string() && credentials_json.at("key").is_string()) {
                    authorizationId = credentials_json.at("id").get<std::string>();
                    authorizationKey = credentials_json.at("key").get<std::string>();
                }
            } catch(const nlohmann::detail::exception& json_exception) {
                std::cerr << "Encountered JSON exception when parsing printer credentials: " << json_exception.what() << std::endl;
            }
        }
    }

    /* ---------- QCustom Plot Widgets Setup & Styling ---------- */
    {
        constexpr const uint32_t plot_resolution = 101;

        // Initialize the plot data vector.
        printBedPlotData = QVector<double>(plot_resolution);
        primaryExtruderPlotData = QVector<double>(plot_resolution);
        secondaryExtruderPlotData = QVector<double>(plot_resolution);

        // Initialize the plot frames vector.
        printBedPlotFrames = QVector<double>(plot_resolution);
        primaryExtruderPlotFrames = QVector<double>(plot_resolution);
        secondaryExtruderPlotFrames = QVector<double>(plot_resolution);

        // Initialize the plot data and frame vectors with default values.
        for(uint32_t i=0; i<plot_resolution; ++i) {
            secondaryExtruderPlotFrames[i] = i;
            primaryExtruderPlotFrames[i] = i;
            printBedPlotFrames[i] = i;

            secondaryExtruderPlotData[i] = 0;
            primaryExtruderPlotData[i] = 0;
            printBedPlotData[i] = 0;
        }

        // Initialize the QCustomPlot instances.
        printBedPlot = new QCustomPlot(this);
        primaryExtruderPlot = new QCustomPlot(this);
        secondaryExtruderPlot = new QCustomPlot(this);

        // Add a new graph to each plot.
        printBedPlot->addGraph();
        primaryExtruderPlot->addGraph();
        secondaryExtruderPlot->addGraph();

        // Printbed Plot Style
        printBedPlot->xAxis->grid()->setVisible(false);
        printBedPlot->yAxis->grid()->setPen(QPen(Qt::darkGreen, 1, Qt::DotLine));
        printBedPlot->setBackground(QBrush(Qt::black));
        printBedPlot->xAxis->setBasePen(QPen(Qt::green, 1));
        printBedPlot->yAxis->setBasePen(QPen(Qt::green, 1));
        printBedPlot->xAxis->setTickPen(QPen(Qt::green, 1));
        printBedPlot->yAxis->setTickPen(QPen(Qt::green, 1));
        printBedPlot->xAxis->setSubTickPen(QPen(Qt::green, 1));
        printBedPlot->yAxis->setSubTickPen(QPen(Qt::green, 1));
        printBedPlot->xAxis->setTickLabelColor(Qt::green);
        printBedPlot->yAxis->setTickLabelColor(Qt::green);
        printBedPlot->xAxis->setLabelColor(Qt::green);
        printBedPlot->yAxis->setLabelColor(Qt::green);
        printBedPlot->graph(0)->setPen(QPen(Qt::green, 1));

        // Primary Extruder Plot Style
        primaryExtruderPlot->xAxis->grid()->setVisible(false);
        primaryExtruderPlot->yAxis->grid()->setPen(QPen(Qt::darkGreen, 1, Qt::DotLine));
        primaryExtruderPlot->setBackground(QBrush(Qt::black));
        primaryExtruderPlot->xAxis->setBasePen(QPen(Qt::green, 1));
        primaryExtruderPlot->yAxis->setBasePen(QPen(Qt::green, 1));
        primaryExtruderPlot->xAxis->setTickPen(QPen(Qt::green, 1));
        primaryExtruderPlot->yAxis->setTickPen(QPen(Qt::green, 1));
        primaryExtruderPlot->xAxis->setSubTickPen(QPen(Qt::green, 1));
        primaryExtruderPlot->yAxis->setSubTickPen(QPen(Qt::green, 1));
        primaryExtruderPlot->xAxis->setTickLabelColor(Qt::green);
        primaryExtruderPlot->yAxis->setTickLabelColor(Qt::green);
        primaryExtruderPlot->xAxis->setLabelColor(Qt::green);
        primaryExtruderPlot->yAxis->setLabelColor(Qt::green);
        primaryExtruderPlot->graph(0)->setPen(QPen(Qt::green, 1));

        // Secondary Extruder Plot Style
        secondaryExtruderPlot->xAxis->grid()->setVisible(false);
        secondaryExtruderPlot->yAxis->grid()->setPen(QPen(Qt::darkGreen, 1, Qt::DotLine));
        secondaryExtruderPlot->setBackground(QBrush(Qt::black));
        secondaryExtruderPlot->xAxis->setBasePen(QPen(Qt::green, 1));
        secondaryExtruderPlot->yAxis->setBasePen(QPen(Qt::green, 1));
        secondaryExtruderPlot->xAxis->setTickPen(QPen(Qt::green, 1));
        secondaryExtruderPlot->yAxis->setTickPen(QPen(Qt::green, 1));
        secondaryExtruderPlot->xAxis->setSubTickPen(QPen(Qt::green, 1));
        secondaryExtruderPlot->yAxis->setSubTickPen(QPen(Qt::green, 1));
        secondaryExtruderPlot->xAxis->setTickLabelColor(Qt::green);
        secondaryExtruderPlot->yAxis->setTickLabelColor(Qt::green);
        secondaryExtruderPlot->xAxis->setLabelColor(Qt::green);
        secondaryExtruderPlot->yAxis->setLabelColor(Qt::green);
        secondaryExtruderPlot->graph(0)->setPen(QPen(Qt::green, 1));

        // // Set the data of the newly created graph for each plot.
        // printBedPlot->graph(0)->setData(printBedPlotFrames, printBedPlotData);
        // primaryExtruderPlot->graph(0)->setData(primaryExtruderPlotFrames, primaryExtruderPlotData);
        // secondaryExtruderPlot->graph(0)->setData(secondaryExtruderPlotFrames, secondaryExtruderPlotData);

        // Set the range of the X axis for each plot.
        printBedPlot->xAxis->setRange(0, plot_resolution);
        primaryExtruderPlot->xAxis->setRange(0, plot_resolution);
        secondaryExtruderPlot->xAxis->setRange(0, plot_resolution);

        // Set the range of the Y axis for each plot.
        printBedPlot->yAxis->setRange(0, 115);
        primaryExtruderPlot->yAxis->setRange(0, 300);
        secondaryExtruderPlot->yAxis->setRange(0, 300);

        // Set the X axis label for each plot.
        printBedPlot->xAxis->setLabel("Frame");
        primaryExtruderPlot->xAxis->setLabel("Frame");
        secondaryExtruderPlot->xAxis->setLabel("Frame");

        // Set the Y axis label for each plot.
        printBedPlot->yAxis->setLabel("Temperature °C");
        primaryExtruderPlot->yAxis->setLabel("Temperature °C");
        secondaryExtruderPlot->yAxis->setLabel("Temperature °C");

        // Replot each plot.
        printBedPlot->replot();
        primaryExtruderPlot->replot();
        secondaryExtruderPlot->replot();

        // Add the plot widgets to their corresponding vertical layouts.
        ui->vlo_bed_plot->addWidget(printBedPlot);
        ui->vlo_ext1_plot->addWidget(primaryExtruderPlot);
        ui->vlo_ext2_plot->addWidget(secondaryExtruderPlot);

    }
}

MainWindow::~MainWindow() {
    printHistoryPollingTimer->stop();
    printjobPollingTimer->stop();
    systemInfoPollingTimer->stop();
    temperaturePollingTimer->stop();
}