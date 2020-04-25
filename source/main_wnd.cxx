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
        if(http_response.Code != 0) http_response.Filled = true;

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

        if(http_response.Code != 0) http_response.Filled = true;

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
        if(http_response.Code != 0) http_response.Filled = true;

        curl_easy_cleanup(curl_session);
        curl_session = nullptr;
    }

    return http_response;
}

// ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// MainWindow Class Definitions

MainWindow::AuthCredentials::operator std::pair<std::string, std::string>() {
    return std::make_pair(Id, Key);
}

MainWindow::AuthCredentials::operator std::pair<std::string, std::string>() const {
    return std::make_pair(Id, Key);
}

bool MainWindow::AuthCredentials::ValidSize() const {
    return (Id.size() == 32 && Key.size() == 64);
}

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
    RaiiExecution raii_execution([this]() -> void {
        handlingResponse = true;
    }, [this]() -> void {
        handlingResponse = false;
    });

    const EndpointData& future_result = temperatureResponses.resultAt(response_index);

    const Http::Response& response = future_result.Response;
    const std::string& response_endpoint = future_result.Endpoint;

    if(response.Filled) {
        switch(response.Code) {
            case 200 : {
                try {
                    const Json& json_response_body = Json::parse(response.Body);

                    if(response_endpoint == ENDP_BED_TEMPERATURE) {
                        const double current_temperature = json_response_body.at("current").get<double>();
                        const double target_temperature = json_response_body.at("target").get<double>();

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
                        const double current_temperature = json_response_body.at("current").get<double>();
                        const double target_temperature = json_response_body.at("target").get<double>();

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
                        const double current_temperature = json_response_body.at("current").get<double>();
                        const double target_temperature = json_response_body.at("target").get<double>();

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
                } catch(nlohmann::detail::exception& json_exception) {
                    std::cerr << json_exception.what() << std::endl;
                }

                break;
            }

            default : {
                std::cerr << "Unhandled HTTP status code: " << response.Code << std::endl;
                break;
            }
        }
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
    RaiiExecution raii_execution([this]() -> void {
        handlingResponse = true;
    }, [this]() -> void {
        handlingResponse = false;
    });


    const EndpointData& future_result = printjobResponse.result();
    const Http::Response& response = future_result.Response;

    if(response.Filled) {
        switch(response.Code) {
            case 200:
            case 201 : {
                try {
                    const Json& response_body_json = Json::parse(response.Body);

                    ui->grp_printjob->setTitle(QString::fromStdString("PRINT JOB - " + response_body_json.at("name").get<std::string>()));

                    const double& time_elapsed = response_body_json.at("time_elapsed").get<double>();
                    const double& time_total = response_body_json.at("time_total").get<double>();

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
                } catch(nlohmann::detail::exception& json_exception) {
                    std::cerr << json_exception.what() << std::endl;
                }

                break;
            }

            case 404 : {
                ui->grp_printjob->setTitle("PRINT JOB");
                ui->prg_printjob->setFormat("NO PRINT JOB");
                ui->prg_printjob->setRange(0, 1);
                ui->prg_printjob->setValue(0);
                break;
            }

            default : {
                std::cerr << "Unhandled HTTP status code: " << response.Code << std::endl;
                break;
            }
        }
    }


    if(response.Code == 200 || response.Code == 201) {
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
    RaiiExecution raii_execution([this]() -> void {
        handlingResponse = true;
    }, [this]() -> void {
        handlingResponse = false;
    });

    const EndpointData& future_result = systemInfoResponse.result();
    const Http::Response& response = future_result.Response;

    if(response.Filled) {
        switch(response.Code) {
            case 200 : {
                try  {
                    const Json& response_body_json = Json::parse(response.Body);

                    ui->pte_syslog->clear();

                    const double& system_uptime = response_body_json.at("uptime").get<double>() / 60 / 60 / 24;
                    ui->lcd_uptime->display(system_uptime);

                    const std::vector<std::string>& log_messages = response_body_json.at("log").get<std::vector<std::string>>();
                    QVector<QString> q_log_messages(static_cast<int32_t>(log_messages.size()));

                    std::transform(log_messages.begin(), log_messages.end(), q_log_messages.begin(), [](const std::string& log_message) -> QString {
                        return QString::fromStdString(log_message);
                    });

                    for(const auto& log_message : q_log_messages) {
                        ui->pte_syslog->appendPlainText(log_message);
                    }

                    const auto& memory = response_body_json.at("memory");

                    uint32_t memory_capacity = memory.at("total").get<uint32_t>();
                    uint32_t memory_usage = memory.at("used").get<uint32_t>();

                    memory_capacity = static_cast<uint32_t>(std::round(static_cast<double>(memory_capacity) / 1024 / 1024));
                    memory_usage = static_cast<uint32_t>(std::round(static_cast<double>(memory_usage) / 1024 / 1024));

                    ui->prg_memory->setRange(0, memory_capacity);
                    ui->prg_memory->setValue(memory_usage);


                } catch(nlohmann::detail::exception& json_exception) {
                    std::cerr << json_exception.what() << std::endl;
                }

                break;
            }

            default : {
                std::cerr << "Unhandled HTTP status code: " << response.Code << std::endl;
                break;
            }
        }
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
    RaiiExecution raii_execution([this]() -> void {
        handlingResponse = true;
    }, [this]() -> void {
        handlingResponse = false;
    });

    const EndpointData& future_result = printHistoryResponse.result();
    const Http::Response& response = future_result.Response;

    if(response.Filled) {
        switch(response.Code) {
            case 200 : {
                try {
                    const Json& response_body_json = Json::parse(response.Body);
                    printHistory->clear();

                    for(const auto& print_job : response_body_json) {
                        const std::string& time_finished = print_job.at("datetime_finished").get<std::string>();
                        const std::string& time_started = print_job.at("datetime_started").get<std::string>();
                        const std::string& source = print_job.at("source").get<std::string>();
                        const std::string& result = print_job.at("result").get<std::string>();
                        const std::string& name = print_job.at("name").get<std::string>();

                        printHistory->addItem(QString::fromStdString(time_started + " - " + time_finished + " | " + name + " (" + source + ") = " + result));
                    }
                } catch(nlohmann::detail::exception& json_exception) {
                    std::cerr << json_exception.what() << std::endl;
                }

                break;
            }

            default : {
                std::cerr << "Unhandled HTTP status code: " << response.Code << std::endl;
                break;
            }
        }
    }
}


/* ---------- Printjob Uploading / Response Handling ---------- */
void MainWindow::on_btn_upload_clicked() {
    const AuthCredentials& auth_credentials = authCredentials.Get();

    if(auth_credentials.ValidSize()) {
        const std::string& printer_ipv4_address = printerIpv4Address.Get();

        if(printer_ipv4_address.size()) {
            const std::string& file_name = QFileDialog::getOpenFileName(this, "Select Spliced GCode", ".", "GCode Files (*.gcode)").toStdString();

            std::ifstream file_stream(file_name, std::ios::binary);

            if(file_stream.good()) {
                ui->btn_upload->setText("Uploading..");

                uploadFinishedResponse = QtConcurrent::run([](const std::string printer_ipv4_address, const std::string file_name, const AuthCredentials auth_credentials) -> Http::Response {
                    Http::Response response = Http::Post(
                         printer_ipv4_address + ENDP_PRINT_JOB,
                         {{"jobname", file_name}},
                         {{"file", file_name}},
                         auth_credentials
                    );

                    return response;
                }, printer_ipv4_address, file_name, auth_credentials);

                uploadFinishedResponseWatcher->setFuture(uploadFinishedResponse);
            } else {
                QMessageBox::warning(this, "I/O Error", "Couldn't open the selected GCode file for reading, ensure you have the correct privilages.");
            }
        } else {
            QMessageBox::warning(this, "Connection Problem", "Not connected to any printer.");
        }
    } else {
        QMessageBox::warning(this, "Credential Problem", "Printer credentials are required for this operation.");
    }
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
    RaiiExecution raii_execution([this]() -> void {
        ui->btn_request_auth->setText("Requesting..");
        ui->btn_request_auth->repaint();
    }, [this]() -> void {
        ui->btn_request_auth->setText("Request Authorization");
    });

    const std::string& printer_ipv4_address = printerIpv4Address.Get();

    if(!printer_ipv4_address.size()) {
        QMessageBox::warning(this, "Connection Problem", "Not connected to any printer.");
        return;
    }

    Http::Response auth_response = Http::Post(
        printer_ipv4_address + ENDP_AUTH_REQUEST, {
            {"application", "Ultimaker-Monitor"},
            {"user", "Ultimaker-Monitor"}
        }, {}, {}
    );

    if(auth_response.Filled) {
        switch(auth_response.Code) {
            case 200 : {
                QMessageBox::information(this, "Code 200", "Printer authorization has been requested, confirm on the printer.");

                std::string recieved_auth_id;
                std::string recieved_auth_key;

                try {
                    const Json& response_json = Json::parse(auth_response.Body);
                    recieved_auth_id = response_json.at("id").get<std::string>();
                    recieved_auth_key = response_json.at("key").get<std::string>();
                } catch(nlohmann::detail::exception& json_exception) {
                    QMessageBox::warning(this, "JSON Parsing Failure", "Failed to parse the response body. Exception: " + QString(json_exception.what()));
                    return;
                }

                bool confirmed_or_denied = false;

                for(uint32_t attempts = 0; !confirmed_or_denied; Sleep(1000)) {
                    if(attempts >= 20) {
                        QMessageBox::warning(this, "Confirmation Timeout", "The requested credentials have neither been confirmed or denied after 20 attempts, giving up.");
                        return;
                    }

                    Http::Response verification_response = Http::Get(printer_ipv4_address + ENDP_AUTH_CHECK + recieved_auth_id, {});

                    switch(verification_response.Code) {
                        case 200 : {
                            std::string response_message;

                            try {
                                const Json& response_json = Json::parse(verification_response.Body);
                                response_message = response_json.at("message").get<std::string>();
                            } catch(nlohmann::detail::exception& json_exception) {
                                QMessageBox::warning(this, "JSON Parsing Failure", "Failed to parse the response body. Exception: " + QString(json_exception.what()));
                                return;
                            }

                            if(response_message == "authorized") {
                                confirmed_or_denied = true;

                                authCredentials = {recieved_auth_id, recieved_auth_key};

                                QMessageBox::StandardButton user_response = QMessageBox::question(
                                    this,
                                    "Authorized",
                                    "The application is now authoried. Would you like to save the authorized credentials?",
                                    QMessageBox::Yes | QMessageBox::No
                                );

                                if(user_response == QMessageBox::Yes) {
                                    std::ofstream credentials_file_stream("./printer-credentials.json", std::ios::binary);

                                    if(credentials_file_stream.good()) {
                                        const Json& credentials_json = {{"id", recieved_auth_id}, {"key", recieved_auth_key}};
                                        const std::string& credentials_string = credentials_json.dump();
                                        credentials_file_stream.write(credentials_string.data(), credentials_string.size());
                                        credentials_file_stream.close();

                                        QMessageBox::information(this, "Credentials Stored", "The authorized credentials have been stored @ printer-credentials.json");
                                    } else {
                                        QMessageBox::warning(this, "I/O Error", "Cannot open printer-credentials.json for writing.");
                                    }
                                }


                            } else if(response_message == "unauthorized") {
                                confirmed_or_denied = true;
                                QMessageBox::information(this, "Unauthorized", "The application has not been authorized.");
                            } else {
                                ++attempts;
                            }

                            break;
                        }

                        default : {
                            QMessageBox::warning(this, "Unhandled Code", "Unhandled HTTP response code: " + QString::number(auth_response.Code));
                            break;
                        }
                    }
                }

                break;
            }

            default : {
                QMessageBox::warning(this, "Unhandled Code", "Unhandled HTTP response code: " + QString::number(auth_response.Code));
                break;
            }
        }
    } else {
        QMessageBox::warning(this, "Timeout", "No response was given from the printer.");
    }
}
void MainWindow::on_btn_connect_clicked() {
    RaiiExecution raii_execution([this]() -> void {
        ui->btn_connect->setText("Connecting..");
        ui->btn_connect->repaint();
    }, [this]() -> void {
        ui->btn_connect->setText("Connect");
    });

    const std::string& new_ipv4_address = ui->lin_address->text().toStdString();

    Http::Response network_check_response = Http::Get(new_ipv4_address + ENDP_NETWORK_INFO, {}, 2);

    if(network_check_response.Filled) {
        switch(network_check_response.Code) {
            case 200 : {
                printerIpv4Address = new_ipv4_address;
                ui->grp_system->setTitle("SYSTEM - " + QString::fromStdString(new_ipv4_address));

                // If pre-existing credentials are loaded, check if they apply to the newly connected printer.
                if(authCredentials.Get().ValidSize()) {
                    Http::Response verification_response = Http::Get(new_ipv4_address + ENDP_AUTH_VERIFICATION, authCredentials.Get());

                    if(verification_response.Filled) {
                        switch(verification_response.Code) {
                            // If the pre-existing credentials apply, continue without a prompt.
                            case 200 : break;

                            // If they don't, re-set the credentials to null and inform the user.
                            case 401 : {
                                authCredentials.Set({"", ""});
                                QMessageBox::warning(this, "Code 401 - Unauthorized", "The credentials loaded in memory don't apply to newly connected printer. Request new authentication.");
                                break;
                            }

                            case 403 : {
                                authCredentials.Set({"", ""});
                                QMessageBox::warning(this, "Code 403 - Forbidden", "The credentials loaded in memory don't apply to newly connected printer. Request new authentication.");
                                break;
                            }

                            default : {
                                QMessageBox::warning(this, "Unhandled Code", "Unhandled HTTP response code: " + QString::number(verification_response.Code));
                                break;
                            }
                        }
                    } else {
                        QMessageBox::warning(this, "Timeout", "No response was given from the printer.");
                    }
                }

                break;
            }

            default : {
                QMessageBox::warning(this, "Unhandled Code", "Unhandled HTTP response code: " + QString::number(network_check_response.Code));
                break;
            }
        }
    } else {
        QMessageBox::warning(this, "Timeout", "No response was given from the printer.");
    }
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
        temperaturePollingTimer->start(100);

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
    const AuthCredentials& auth_credentials = authCredentials.Get();

    if(auth_credentials.ValidSize()) {
        const std::string& printer_ipv4_address = printerIpv4Address.Get();

        if(printer_ipv4_address.size()) {
            Http::Response abort_response = Http::Put(
                printer_ipv4_address + ENDP_PRINTJOB_STATE,
                "{\"target\":\"abort\"}",
                auth_credentials,
                1
            );

            if(abort_response.Filled) {
                switch(abort_response.Code) {
                    case 204: break;
                    case 201: break;

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
        } else {
            QMessageBox::warning(this, "Connection Problem", "Not connected to any printer.");
        }
    } else {
        QMessageBox::warning(this, "Credential Problem", "Printer credentials are required for this operation.");
    }
}
void MainWindow::on_btn_pause_clicked() {
    const AuthCredentials& auth_credentials = authCredentials.Get();

    if(auth_credentials.ValidSize()) {
        const std::string& printer_ipv4_address = printerIpv4Address.Get();

        if(printer_ipv4_address.size()) {
            Http::Response pause_response = Http::Put(
                printer_ipv4_address + ENDP_PRINTJOB_STATE,
                "{\"target\":\"pause\"}",
                auth_credentials,
                1
            );

            if(pause_response.Filled) {
                switch(pause_response.Code) {
                    case 204: break;
                    case 201: break;

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
        } else {
            QMessageBox::warning(this, "Connection Problem", "Not connected to any printer.");
        }
    } else {
        QMessageBox::warning(this, "Credential Problem", "Printer credentials are required for this operation.");
    }
}
void MainWindow::on_btn_resume_clicked() {
    const AuthCredentials& auth_credentials = authCredentials.Get();

    if(auth_credentials.ValidSize()) {
        const std::string& printer_ipv4_address = printerIpv4Address.Get();

        if(printer_ipv4_address.size()) {
            Http::Response resume_response = Http::Put(
                printer_ipv4_address + ENDP_PRINTJOB_STATE,
                "{\"target\":\"print\"}",
                auth_credentials,
                1
            );

            if(resume_response.Filled) {
                switch(resume_response.Code) {
                    case 204: break;
                    case 201: break;

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
        } else {
            QMessageBox::warning(this, "Connection Problem", "Not connected to any printer.");
        }
    } else {
        QMessageBox::warning(this, "Credential Problem", "Printer credentials are required for this operation.");
    }
}

/* ---------- Constructor & Destructor ---------- */
MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    /* ---------- Default Variable Values ---------- */
    {
        authCredentials = {"", ""};

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

            const std::string& credentials_json_string = std::string(file_bytes.begin(), file_bytes.end());

            try {
                const Json& credentials_json = Json::parse(credentials_json_string);

                authCredentials = {
                    credentials_json.at("id").get<std::string>(),
                    credentials_json.at("key").get<std::string>()
                };
            } catch(const nlohmann::detail::exception& json_exception) {
                QMessageBox::warning(this, "Parsing Error", "Could not parse printer-credentials.json - perhaps it's not valid JSON.");
            }
        }
    }

    /* ---------- QCustom Plot Widgets Setup & Styling ---------- */
    {
        constexpr const uint32_t plot_resolution = 501;

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