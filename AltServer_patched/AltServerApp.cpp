//
//  AltServerApp.cpp
//  AltServer-Windows
//
//  Created by Riley Testut on 8/30/19.
//  Copyright (c) 2019 Riley Testut. All rights reserved.
//

#include "AltServerApp.h"

#include "AppleAPI.hpp"
#include "ConnectionManager.hpp"
#include "InstallError.hpp"
#include "Signer.hpp"
#include "DeviceManager.hpp"
#include "Archiver.hpp"
#include "ServerError.hpp"

#include "AnisetteDataManager.h"

#include <cpprest/http_client.h>
#include <cpprest/filestream.h>

#include <filesystem>
#include <regex>
#include <numeric>

#include <plist/plist.h>

#include <WS2tcpip.h>




#define odslog(msg) { std::stringstream ss; ss << msg << std::endl; OutputDebugStringA(ss.str().c_str()); }

using namespace utility;                    // Common utilities like string conversions
using namespace web;                        // Common features like URIs.
using namespace web::http;                  // Common HTTP functionality
using namespace web::http::client;          // HTTP client features
using namespace concurrency::streams;       // Asynchronous streams

namespace fs = std::filesystem;

extern std::string temporary_directory();
extern std::string make_uuid();
extern std::vector<unsigned char> readFile(const char* filename);

extern std::string StringFromWideString(std::string wideString);
extern std::string WideStringFromString(std::string string);


#define IDCANCEL 0
#define MessageBox(x, content, title, xx) (this->ShowAlert(title, content " (Ctrl-C to avoid)"), 1)

// Observes all exceptions that occurred in all tasks in the given range.
template<class T, class InIt>
void observe_all_exceptions(InIt first, InIt last)
{
	// TODO: FIX THIS
}

AltServerApp* AltServerApp::_instance = nullptr;

AltServerApp* AltServerApp::instance()
{
	if (_instance == 0)
	{
		_instance = new AltServerApp();
	}

	return _instance;
}

AltServerApp::AltServerApp() : _appGroupSemaphore(1)
{
}

AltServerApp::~AltServerApp()
{
}

pplx::task<std::shared_ptr<Application>> AltServerApp::InstallApplication(std::optional<std::string> filepath, std::shared_ptr<Device> installDevice, std::string appleID, std::string password)
{
    auto appName = filepath.has_value() ? fs::path(*filepath).filename().string() : "AltStore";
    auto localizedFailure = "Could not install " + appName + " to " + installDevice->name() + ".";

	return this->_InstallApplication(filepath, installDevice, appleID, password)
	.then([=](pplx::task<std::shared_ptr<Application>> task) -> pplx::task<std::shared_ptr<Application>> {
		try
		{
			auto application = task.get();
			return pplx::create_task([application]() { 
				return application;
			});
		}
		catch (APIError& error)
		{
			if ((APIErrorCode)error.code() == APIErrorCode::InvalidAnisetteData)
			{
				// Our attempt to re-provision the device as a Mac failed, so reset provisioning and try one more time.
				// This appears to happen when iCloud is running simultaneously, and just happens to provision device at same time as AltServer.
				AnisetteDataManager::instance()->ResetProvisioning();

				this->ShowNotification("Registering PC with Apple...", "This may take a few seconds.");

				// Provisioning device can fail if attempted too soon after previous attempt.
				// As a hack around this, we wait a bit before trying again.
				// 10-11 seconds appears to be too short, so wait for 12 seconds instead.
				Sleep(12000);

				return this->_InstallApplication(filepath, installDevice, appleID, password);
			}
			else
			{
				throw;
			}
		}
	})
	.then([=](pplx::task<std::shared_ptr<Application>> task) -> std::shared_ptr<Application> {
		try
		{
			auto application = task.get();

			std::stringstream ss;
			ss << application->name() << " was successfully installed on " << installDevice->name() << ".";

			this->ShowNotification("Installation Succeeded", ss.str());

			return application;
		}
		catch (InstallError& error)
		{
			if ((InstallErrorCode)error.code() == InstallErrorCode::Cancelled)
			{
				// Ignore
			}
			else
			{
                this->ShowErrorAlert(error, localizedFailure);
                throw;
			}
		}
		catch (APIError& error)
		{
			if ((APIErrorCode)error.code() == APIErrorCode::InvalidAnisetteData)
			{
				AnisetteDataManager::instance()->ResetProvisioning();
			}

            this->ShowErrorAlert(error, localizedFailure);
            throw;
		}
		catch (AnisetteError& error)
		{
			this->HandleAnisetteError(error);
            throw;
		}
		catch (std::exception& exception)
		{
            this->ShowErrorAlert(exception, localizedFailure);
            throw;
		}
	});
}

pplx::task<std::shared_ptr<Application>> AltServerApp::_InstallApplication(std::optional<std::string> filepath, std::shared_ptr<Device> installDevice, std::string appleID, std::string password)
{
    fs::path destinationDirectoryPath(temporary_directory());
    destinationDirectoryPath.append(make_uuid());
    
	auto account = std::make_shared<Account>();
	auto app = std::make_shared<Application>();
	auto team = std::make_shared<Team>();
	auto device = std::make_shared<Device>();
	auto appID = std::make_shared<AppID>();
	auto certificate = std::make_shared<Certificate>();
	auto profile = std::make_shared<ProvisioningProfile>();

	auto session = std::make_shared<AppleAPISession>();

	return pplx::create_task([=]() {
		auto anisetteData = AnisetteDataManager::instance()->FetchAnisetteData();
		return this->Authenticate(appleID, password, anisetteData);
	})
    .then([=](std::pair<std::shared_ptr<Account>, std::shared_ptr<AppleAPISession>> pair)
          {
              *account = *(pair.first);
			  *session = *(pair.second);

			  odslog("Fetching team...");

              return this->FetchTeam(account, session);
          })
    .then([=](std::shared_ptr<Team> tempTeam)
          {
			odslog("Registering device...");

              *team = *tempTeam;
              return this->RegisterDevice(installDevice, team, session);
          })
    .then([=](std::shared_ptr<Device> tempDevice)
          {
				odslog("Fetching certificate...");

				tempDevice->setOSVersion(installDevice->osVersion());
				*device = *tempDevice;

				return this->FetchCertificate(team, session);
          })
    .then([=](std::shared_ptr<Certificate> tempCertificate)
          {
				*certificate = *tempCertificate;

				odslog("Preparing device...");				
                return this->PrepareDevice(device).then([=](pplx::task<void> task) {
                    try
                    {
                        // Don't rethrow error, and instead continue installing app even if we couldn't install Developer disk image.
                        task.get();
                    }
                    catch (Error& error)
                    {
                        odslog("Failed to install DeveloperDiskImage.dmg to " << *device << ". " << error.localizedDescription());
                    }
                    catch (std::exception& exception)
                    {
                        odslog("Failed to install DeveloperDiskImage.dmg to " << *device << ". " << exception.what());
                    }

                    if (filepath.has_value())
                    {
                        odslog("Importing app...");

                        return pplx::create_task([filepath] {
                            return fs::path(*filepath);
                        });
                    }
                    else
                    {
                        odslog("Downloading app...");

                        // Show alert before downloading AltStore.
                        this->ShowInstallationNotification("AltStore", device->name());
                        return this->DownloadApp();
                    }
                });
          })
    .then([=](fs::path downloadedAppPath)
          {
			odslog("Downloaded app!");

              fs::create_directory(destinationDirectoryPath);
              
              auto appBundlePath = UnzipAppBundle(downloadedAppPath.string(), destinationDirectoryPath.string());
			  auto app = std::make_shared<Application>(appBundlePath);

			  if (filepath.has_value())
			  {
				  // Show alert after "downloading" local .ipa.
				  this->ShowInstallationNotification(app->name(), device->name());
			  }
			  else
			  {
				  // Remove downloaded app.

				  try
				  {
					  fs::remove(downloadedAppPath);
				  }
				  catch (std::exception& e)
				  {
					  odslog("Failed to remove downloaded .ipa." << e.what());
				  }
			  }              
              
              return app;
          })
    .then([=](std::shared_ptr<Application> tempApp)
          {
              *app = *tempApp;
			  return this->PrepareAllProvisioningProfiles(app, device, team, session);
          })
    .then([=](std::map<std::string, std::shared_ptr<ProvisioningProfile>> profiles)
          {
              return this->InstallApp(app, device, team, certificate, profiles);
          })
    .then([=](pplx::task<std::shared_ptr<Application>> task)
          {
			if (fs::exists(destinationDirectoryPath))
			{
				fs::remove_all(destinationDirectoryPath);
			}     

			try
			{
				auto application = task.get();
				return application;
			}
			catch (LocalizedError& error)
			{
				if (error.code() == -22421)
				{
					// Don't know what API call returns this error code, so assume any LocalizedError with -22421 error code
					// means invalid anisette data, then throw the correct APIError.
					throw APIError(APIErrorCode::InvalidAnisetteData);
				}
				else if (error.code() == -29004)
				{
					// Same with -29004, "Environment Mismatch"
					throw APIError(APIErrorCode::InvalidAnisetteData);
				}
				else
				{
					throw;
				}
			}
         });
}

pplx::task<void> AltServerApp::PrepareDevice(std::shared_ptr<Device> device)
{
	return DeviceManager::instance()->IsDeveloperDiskImageMounted(device)
	.then([=](bool isMounted) {
		if (isMounted)
		{
			return pplx::create_task([] { return; });
		}
		else
		{
			return this->_developerDiskManager.DownloadDeveloperDisk(device)
			.then([=](std::pair<std::string, std::string> paths) {
				return DeviceManager::instance()->InstallDeveloperDiskImage(paths.first, paths.second, device);
			})
			.then([=](pplx::task<void> task) {
				try
				{
					task.get();

					// No error thrown, so assume disk is compatible.
					this->_developerDiskManager.SetDeveloperDiskCompatible(true, device);
				}
				catch (ServerError& serverError)
				{
					if (serverError.code() == (int)ServerErrorCode::IncompatibleDeveloperDisk)
					{
						// Developer disk is not compatible with this device, so mark it as incompatible.
						this->_developerDiskManager.SetDeveloperDiskCompatible(false, device);
					}
					else
					{
						// Don't mark developer disk as incompatible because it probably failed for a different reason.
					}

					throw;
				}
			});
		}		
	});
}

pplx::task<fs::path> AltServerApp::DownloadApp()
{
    fs::path temporaryPath(temporary_directory());
    temporaryPath.append(make_uuid());
    
    auto outputFile = std::make_shared<ostream>();
    
    // Open stream to output file.
    auto task = fstream::open_ostream(WideStringFromString(temporaryPath.string()))
    .then([=](ostream file)
          {
			*outputFile = file;
              
	        #if BETA
			uri_builder builder(U("https://cdn.altstore.io/file/altstore/altstore-beta.ipa"));
	        #else
			uri_builder builder(U("https://cdn.altstore.io/file/altstore/altstore.ipa"));
			#endif
              
			http_client client(builder.to_uri());
			return client.request(methods::GET);
          })
    .then([=](http_response response)
          {
              printf("Received download response status code:%u\n", response.status_code());
              
              // Write response body into the file.
              return response.body().read_to_end(outputFile->streambuf());
          })
    .then([=](size_t)
          {
              outputFile->close();
              return temporaryPath;
          });
    
    return task;
}
pplx::task<std::shared_ptr<Team>> AltServerApp::FetchTeam(std::shared_ptr<Account> account, std::shared_ptr<AppleAPISession> session)
{
    auto task = AppleAPI::getInstance()->FetchTeams(account, session)
    .then([](std::vector<std::shared_ptr<Team>> teams) {

		for (auto& team : teams)
		{
			if (team->type() == Team::Type::Individual)
			{
				return team;
			}
		}

		for (auto& team : teams)
		{
			if (team->type() == Team::Type::Free)
			{
				return team;
			}
		}

		for (auto& team : teams)
		{
			return team;
		}

		throw InstallError(InstallErrorCode::NoTeam);
    });
    
    return task;
}

pplx::task<std::shared_ptr<Certificate>> AltServerApp::FetchCertificate(std::shared_ptr<Team> team, std::shared_ptr<AppleAPISession> session)
{
    auto task = AppleAPI::getInstance()->FetchCertificates(team, session)
    .then([this, team, session](std::vector<std::shared_ptr<Certificate>> certificates)
          {
			auto certificatesDirectoryPath = this->certificatesDirectoryPath();
			auto cachedCertificatePath = certificatesDirectoryPath.append(team->identifier() + ".p12");

			std::shared_ptr<Certificate> preferredCertificate = nullptr;

			for (auto& certificate : certificates)
			{
				if (!certificate->machineName().has_value())
				{
					continue;
				}

				std::string prefix("AltStore");

				if (certificate->machineName()->size() < prefix.size())
				{
					// Machine name doesn't begin with "AltStore", so ignore.
					continue;
				}
				else
				{
					auto result = std::mismatch(prefix.begin(), prefix.end(), certificate->machineName()->begin());
					if (result.first != prefix.end())
					{
						// Machine name doesn't begin with "AltStore", so ignore.
						continue;
					}
				}

				if (fs::exists(cachedCertificatePath) && certificate->machineIdentifier().has_value())
				{
					try
					{
						auto data = readFile(cachedCertificatePath.string().c_str());
						auto cachedCertificate = std::make_shared<Certificate>(data, *certificate->machineIdentifier());

						// Manually set machineIdentifier so we can encrypt + embed certificate if needed.
						cachedCertificate->setMachineIdentifier(*certificate->machineIdentifier());

						return pplx::create_task([cachedCertificate] {
							return cachedCertificate;
						});
					}
					catch(std::exception &e)
					{
						// Ignore cached certificate errors.
						odslog("Failed to load cached certificate:" << cachedCertificatePath << ". " << e.what())
					}
				}

				preferredCertificate = certificate;

				// Machine name starts with AltStore.

				auto alertResult = MessageBox(NULL,
					U("Please use the same AltServer you previously used with this Apple ID, or else apps installed with other AltServers will stop working.\n\nAre you sure you want to continue?"),
					U("Installing AltStore with Multiple AltServers Not Supported"),
					MB_OKCANCEL);

				if (alertResult == IDCANCEL)
				{
					throw InstallError(InstallErrorCode::Cancelled);
				}

				break;
			}

              if (certificates.size() != 0)
              {
                  auto certificate = (preferredCertificate != nullptr) ? preferredCertificate : certificates[0];
                  return AppleAPI::getInstance()->RevokeCertificate(certificate, team, session).then([this, team, session](bool success)
                                                                                            {
                                                                                                return this->FetchCertificate(team, session);
                                                                                            });
              }
              else
              {
                  std::string machineName = "AltStore";
                  
                  return AppleAPI::getInstance()->AddCertificate(machineName, team, session)
					  .then([team, session, cachedCertificatePath](std::shared_ptr<Certificate> addedCertificate)
                        {
                            auto privateKey = addedCertificate->privateKey();
                            if (privateKey == std::nullopt)
                            {
                                throw InstallError(InstallErrorCode::MissingPrivateKey);
                            }
                                                                                             
                            return AppleAPI::getInstance()->FetchCertificates(team, session)
                            .then([privateKey, addedCertificate, cachedCertificatePath](std::vector<std::shared_ptr<Certificate>> certificates)
                                {
                                    std::shared_ptr<Certificate> certificate = nullptr;
                                                                                                       
                                    for (auto tempCertificate : certificates)
                                    {
                                        if (tempCertificate->serialNumber() == addedCertificate->serialNumber())
                                        {
                                            certificate = tempCertificate;
                                            break;
                                        }
                                    }
                                                                                                       
                                    if (certificate == nullptr)
                                    {
                                        throw InstallError(InstallErrorCode::MissingCertificate);
                                    }
                                                                                                       
                                    certificate->setPrivateKey(privateKey);

									try
									{
										if (certificate->machineIdentifier().has_value())
										{
											auto machineIdentifier = certificate->machineIdentifier();

											auto encryptedData = certificate->encryptedP12Data(*machineIdentifier);
											if (encryptedData.has_value())
											{
												std::ofstream fout(cachedCertificatePath.string(), std::ios::out | std::ios::binary);
												fout.write((const char*)encryptedData->data(), encryptedData->size());
												fout.close();
											}
										}
									}
									catch (std::exception& e)
									{
										// Ignore caching certificate errors.
										odslog("Failed to cache certificate:" << cachedCertificatePath << ". " << e.what())
									}

                                    return certificate;
                                });
                        });
              }
          });
    
    return task;
}

pplx::task<std::map<std::string, std::shared_ptr<ProvisioningProfile>>> AltServerApp::PrepareAllProvisioningProfiles(
	std::shared_ptr<Application> application,
	std::shared_ptr<Device> device,
	std::shared_ptr<Team> team,
	std::shared_ptr<AppleAPISession> session)
{
	return this->PrepareProvisioningProfile(application, std::nullopt, device, team, session)
	.then([=](std::shared_ptr<ProvisioningProfile> profile) {
		std::vector<pplx::task<std::pair<std::string, std::shared_ptr<ProvisioningProfile>>>> tasks;

		auto task = pplx::create_task([application, profile]() -> std::pair<std::string, std::shared_ptr<ProvisioningProfile>> { 
			return std::make_pair(application->bundleIdentifier(), profile); 
		});
		tasks.push_back(task);

		for (auto appExtension : application->appExtensions())
		{
			auto task = this->PrepareProvisioningProfile(appExtension, application, device, team, session)
			.then([appExtension](std::shared_ptr<ProvisioningProfile> profile) {
				return std::make_pair(appExtension->bundleIdentifier(), profile);
			});
			tasks.push_back(task);
		}

		return pplx::when_all(tasks.begin(), tasks.end())
			.then([tasks](pplx::task<std::vector<std::pair<std::string, std::shared_ptr<ProvisioningProfile>>>> task) {
				try
				{
					auto pairs = task.get();

					std::map<std::string, std::shared_ptr<ProvisioningProfile>> profiles;
					for (auto& pair : pairs)
					{
						profiles[pair.first] = pair.second;
					}

					observe_all_exceptions<std::pair<std::string, std::shared_ptr<ProvisioningProfile>>>(tasks.begin(), tasks.end());
					return profiles;
				}
				catch (std::exception& e)
				{
					observe_all_exceptions<std::pair<std::string, std::shared_ptr<ProvisioningProfile>>>(tasks.begin(), tasks.end());
					throw;
				}
		});
	});
}

pplx::task<std::shared_ptr<ProvisioningProfile>> AltServerApp::PrepareProvisioningProfile(
	std::shared_ptr<Application> app,
	std::optional<std::shared_ptr<Application>> parentApp,
	std::shared_ptr<Device> device,
	std::shared_ptr<Team> team,
	std::shared_ptr<AppleAPISession> session)
{
	std::string preferredName;
	std::string parentBundleID;

	if (parentApp.has_value())
	{
		parentBundleID = (*parentApp)->bundleIdentifier();
		preferredName = (*parentApp)->name() + " " + app->name();
	}
	else
	{
		parentBundleID = app->bundleIdentifier();
		preferredName = app->name();
	}

	std::string updatedParentBundleID;

	if (app->isAltStoreApp())
	{
		std::stringstream ss;
		ss << "com." << team->identifier() << "." << parentBundleID;

		updatedParentBundleID = ss.str();
	}
	else
	{
		updatedParentBundleID = parentBundleID + "." + team->identifier();
	}

	std::string bundleID = std::regex_replace(app->bundleIdentifier(), std::regex(parentBundleID), updatedParentBundleID);

	return this->RegisterAppID(preferredName, bundleID, team, session)
	.then([=](std::shared_ptr<AppID> appID)
	{
		return this->UpdateAppIDFeatures(appID, app, team, session);
	})
	.then([=](std::shared_ptr<AppID> appID)
	{
		return this->UpdateAppIDAppGroups(appID, app, team, session);
	})
	.then([=](std::shared_ptr<AppID> appID)
	{
		return this->FetchProvisioningProfile(appID, device, team, session);
	})
	.then([=](std::shared_ptr<ProvisioningProfile> profile)
	{
		return profile;
	});
}

pplx::task<std::shared_ptr<AppID>> AltServerApp::RegisterAppID(std::string appName, std::string bundleID, std::shared_ptr<Team> team, std::shared_ptr<AppleAPISession> session)
{
    auto task = AppleAPI::getInstance()->FetchAppIDs(team, session)
    .then([bundleID, appName, team, session](std::vector<std::shared_ptr<AppID>> appIDs)
          {
              std::shared_ptr<AppID> appID = nullptr;
              
              for (auto tempAppID : appIDs)
              {
                  if (tempAppID->bundleIdentifier() == bundleID)
                  {
                      appID = tempAppID;
                      break;
                  }
              }
              
              if (appID != nullptr)
              {
                  return pplx::task<std::shared_ptr<AppID>>([appID]()
                                                            {
                                                                return appID;
                                                            });
              }
              else
              {
                  return AppleAPI::getInstance()->AddAppID(appName, bundleID, team, session);
              }
          });
    
    return task;
}

pplx::task<std::shared_ptr<AppID>> AltServerApp::UpdateAppIDFeatures(std::shared_ptr<AppID> appID, std::shared_ptr<Application> app, std::shared_ptr<Team> team, std::shared_ptr<AppleAPISession> session)
{
	auto entitlements = app->entitlements();

	std::map<std::string, plist_t> features;
	for (auto& pair : entitlements)
	{
		auto feature = ALTFeatureForEntitlement(pair.first);
		if (feature.has_value())
		{
			features[*feature] = pair.second;
		}
	}

	auto appGroups = entitlements[ALTEntitlementAppGroups];
	plist_t appGroupNode = NULL;
	
	if (appGroups != NULL && plist_array_get_size(appGroups) > 0)
	{
		// App uses app groups, so assign `true` to enable the feature.
		appGroupNode = plist_new_bool(true);
	}
	else
	{
		// App has no app groups, so assign `false` to disable the feature.
		appGroupNode = plist_new_bool(false);
	}

	features[ALTFeatureAppGroups] = appGroupNode;

	bool updateFeatures = false;

	// Determine whether the required features are already enabled for the AppID.
	for (auto& pair : features)
	{
		plist_t currentValue = appID->features()[pair.first];
		plist_t newValue = pair.second;

		std::optional<bool> newBoolValue = std::nullopt;
		if (PLIST_IS_BOOLEAN(newValue))
		{
			uint8_t isEnabled = false;
			plist_get_bool_val(newValue, &isEnabled);
			newBoolValue = isEnabled;
		}

		if (currentValue != NULL && plist_compare_node_value(currentValue, newValue))
		{
			// AppID already has this feature enabled and the values are the same.
			continue;
		}
		else if (currentValue == NULL && newBoolValue == false)
		{
			// AppID doesn't already have this feature enabled, but we want it disabled anyway.
			continue;
		}
		else
		{
			// AppID either doesn't have this feature enabled or the value has changed,
			// so we need to update it to reflect new values.
			updateFeatures = true;
			break;
		}
	}

	if (updateFeatures)
	{
		std::shared_ptr<AppID> copiedAppID = std::make_shared<AppID>(*appID);
		copiedAppID->setFeatures(features);

		plist_free(appGroupNode);

		return AppleAPI::getInstance()->UpdateAppID(copiedAppID, team, session);
	}
	else
	{
		plist_free(appGroupNode);

		return pplx::create_task([appID]() {
			return appID;
		});
	}
}

pplx::task<std::shared_ptr<AppID>> AltServerApp::UpdateAppIDAppGroups(std::shared_ptr<AppID> appID, std::shared_ptr<Application> app, std::shared_ptr<Team> team, std::shared_ptr<AppleAPISession> session)
{
	return pplx::create_task([=]() -> pplx::task<std::shared_ptr<AppID>> {
		auto applicationGroupsNode = app->entitlements()[ALTEntitlementAppGroups];
		std::vector<std::string> applicationGroups;

		if (applicationGroupsNode != nullptr)
		{
			for (int i = 0; i < plist_array_get_size(applicationGroupsNode); i++)
			{
				auto groupNode = plist_array_get_item(applicationGroupsNode, i);

				char* groupName = nullptr;
				plist_get_string_val(groupNode, &groupName);

				applicationGroups.push_back(groupName);
			}
		}

		if (applicationGroups.size() == 0)
		{
			// Assigning an App ID to an empty app group array fails,
			// so just do nothing if there are no app groups.
			return pplx::create_task([appID]() {
				return appID;
			});
		}

		this->_appGroupSemaphore.wait();

		return AppleAPI::getInstance()->FetchAppGroups(team, session)
		.then([=](std::vector<std::shared_ptr<AppGroup>> fetchedGroups) {

			std::vector<pplx::task<std::shared_ptr<AppGroup>>> tasks;

			for (auto groupIdentifier : applicationGroups)
			{
				std::string adjustedGroupIdentifier = groupIdentifier + "." + team->identifier();
				std::optional<std::shared_ptr<AppGroup>> matchingGroup;

				for (auto group : fetchedGroups)
				{
					if (group->groupIdentifier() == adjustedGroupIdentifier)
					{
						matchingGroup = group;
						break;
					}
				}

				if (matchingGroup.has_value())
				{
					auto task = pplx::create_task([matchingGroup]() { return *matchingGroup; });
					tasks.push_back(task);
				}
				else
				{
					std::string name = std::regex_replace("AltStore " + groupIdentifier, std::regex("\\."), " ");

					auto task = AppleAPI::getInstance()->AddAppGroup(name, adjustedGroupIdentifier, team, session);
					tasks.push_back(task);
				}				
			}

			return pplx::when_all(tasks.begin(), tasks.end()).then([=](pplx::task<std::vector<std::shared_ptr<AppGroup>>> task) {
				try
				{
					auto groups = task.get();
					observe_all_exceptions<std::shared_ptr<AppGroup>>(tasks.begin(), tasks.end());
					return groups;
				}
				catch (std::exception& e)
				{
					observe_all_exceptions<std::shared_ptr<AppGroup>>(tasks.begin(), tasks.end());
					throw;
				}
			});
		})
		.then([=](std::vector<std::shared_ptr<AppGroup>> groups) {
			return AppleAPI::getInstance()->AssignAppIDToGroups(appID, groups, team, session);
		})
		.then([appID](bool result) {
			return appID;
		})
		.then([this](pplx::task<std::shared_ptr<AppID>> task) {
			this->_appGroupSemaphore.notify();

			auto appID = task.get();
			return appID;
		});
	});
}

pplx::task<std::shared_ptr<Device>> AltServerApp::RegisterDevice(std::shared_ptr<Device> device, std::shared_ptr<Team> team, std::shared_ptr<AppleAPISession> session)
{
    auto task = AppleAPI::getInstance()->FetchDevices(team, device->type(), session)
    .then([device, team, session](std::vector<std::shared_ptr<Device>> devices)
          {
              std::shared_ptr<Device> matchingDevice = nullptr;
              
              for (auto tempDevice : devices)
              {
                  if (tempDevice->identifier() == device->identifier())
                  {
                      matchingDevice = tempDevice;
                      break;
                  }
              }
              
              if (matchingDevice != nullptr)
              {
                  return pplx::task<std::shared_ptr<Device>>([matchingDevice]()
                                                             {
                                                                 return matchingDevice;
                                                             });
              }
              else
              {
                  return AppleAPI::getInstance()->RegisterDevice(device->name(), device->identifier(), device->type(), team, session);
              }
          });
    
    return task;
}

pplx::task<std::shared_ptr<ProvisioningProfile>> AltServerApp::FetchProvisioningProfile(std::shared_ptr<AppID> appID, std::shared_ptr<Device> device, std::shared_ptr<Team> team, std::shared_ptr<AppleAPISession> session)
{
    return AppleAPI::getInstance()->FetchProvisioningProfile(appID, device->type(), team, session);
}

pplx::task<std::shared_ptr<Application>> AltServerApp::InstallApp(std::shared_ptr<Application> app,
                            std::shared_ptr<Device> device,
                            std::shared_ptr<Team> team,
                            std::shared_ptr<Certificate> certificate,
                            std::map<std::string, std::shared_ptr<ProvisioningProfile>> profilesByBundleID)
{
	auto prepareInfoPlist = [profilesByBundleID](std::shared_ptr<Application> app, plist_t additionalValues){
		auto profile = profilesByBundleID.at(app->bundleIdentifier());

		fs::path infoPlistPath(app->path());
		infoPlistPath.append("Info.plist");

		auto data = readFile(infoPlistPath.string().c_str());

		plist_t plist = nullptr;
		plist_from_memory((const char*)data.data(), (int)data.size(), &plist);
		if (plist == nullptr)
		{
			throw InstallError(InstallErrorCode::MissingInfoPlist);
		}

		plist_dict_set_item(plist, "CFBundleIdentifier", plist_new_string(profile->bundleIdentifier().c_str()));
		plist_dict_set_item(plist, "ALTBundleIdentifier", plist_new_string(app->bundleIdentifier().c_str()));

		if (additionalValues != NULL)
		{
			plist_dict_merge(&plist, additionalValues);
		}

		plist_t entitlements = profile->entitlements();
		if (entitlements != nullptr && plist_dict_get_item(entitlements, ALTEntitlementAppGroups) != nullptr)
		{
            plist_t appGroups = plist_copy(plist_dict_get_item(entitlements, ALTEntitlementAppGroups));
            plist_dict_set_item(plist, "ALTAppGroups", appGroups);
		}

		char* plistXML = nullptr;
		uint32_t length = 0;
		plist_to_xml(plist, &plistXML, &length);

		std::ofstream fout(infoPlistPath.string(), std::ios::out | std::ios::binary);
		fout.write(plistXML, length);
		fout.close();
	};

    return pplx::task<std::shared_ptr<Application>>([=]() {
        fs::path infoPlistPath(app->path());
        infoPlistPath.append("Info.plist");
        
        auto data = readFile(infoPlistPath.string().c_str());
        
        plist_t plist = nullptr;
        plist_from_memory((const char *)data.data(), (int)data.size(), &plist);
        if (plist == nullptr)
        {
            throw InstallError(InstallErrorCode::MissingInfoPlist);
        }
        
		plist_t additionalValues = plist_new_dict();

		std::string openAppURLScheme = "altstore-" + app->bundleIdentifier();

		plist_t allURLSchemes = plist_dict_get_item(plist, "CFBundleURLTypes");
		if (allURLSchemes == nullptr)
		{
			allURLSchemes = plist_new_array();
		}
		else
		{
			allURLSchemes = plist_copy(allURLSchemes);
		}

		plist_t altstoreURLScheme = plist_new_dict();
		plist_dict_set_item(altstoreURLScheme, "CFBundleTypeRole", plist_new_string("Editor"));
		plist_dict_set_item(altstoreURLScheme, "CFBundleURLName", plist_new_string(app->bundleIdentifier().c_str()));

		plist_t schemesNode = plist_new_array();
		plist_array_append_item(schemesNode, plist_new_string(openAppURLScheme.c_str()));
		plist_dict_set_item(altstoreURLScheme, "CFBundleURLSchemes", schemesNode);

		plist_array_append_item(allURLSchemes, altstoreURLScheme);
		plist_dict_set_item(additionalValues, "CFBundleURLTypes", allURLSchemes);

		if (app->isAltStoreApp())
		{
			plist_dict_set_item(additionalValues, "ALTDeviceID", plist_new_string(device->identifier().c_str()));

			auto serverID = this->serverID();
			plist_dict_set_item(additionalValues, "ALTServerID", plist_new_string(serverID.c_str()));

			auto machineIdentifier = certificate->machineIdentifier();
			if (machineIdentifier.has_value())
			{
				auto encryptedData = certificate->encryptedP12Data(*machineIdentifier);
				if (encryptedData.has_value())
				{
					plist_dict_set_item(additionalValues, "ALTCertificateID", plist_new_string(certificate->serialNumber().c_str()));

					// Embed encrypted certificate in app bundle.
					fs::path certificatePath(app->path());
					certificatePath.append("ALTCertificate.p12");

					std::ofstream fout(certificatePath.string(), std::ios::out | std::ios::binary);
					fout.write((const char*)encryptedData->data(), encryptedData->size());
					fout.close();
				}
			}
		}
        else if (plist_dict_get_item(plist, "ALTDeviceID") != NULL)
        {
            // There is an ALTDeviceID entry, so assume the app is using AltKit and replace it with the device's UDID.
            plist_dict_set_item(additionalValues, "ALTDeviceID", plist_new_string(device->identifier().c_str()));

			auto serverID = this->serverID();
			plist_dict_set_item(additionalValues, "ALTServerID", plist_new_string(serverID.c_str()));
        }

		prepareInfoPlist(app, additionalValues);

		for (auto appExtension : app->appExtensions())
		{
			prepareInfoPlist(appExtension, NULL);
		}

		std::vector<std::shared_ptr<ProvisioningProfile>> profiles;
		std::set<std::string> profileIdentifiers;
		for (auto pair : profilesByBundleID)
		{
			profiles.push_back(pair.second);
			profileIdentifiers.insert(pair.second->bundleIdentifier());
		}
        
        Signer signer(team, certificate);
        signer.SignApp(app->path(), profiles);
        

// DEBUG: preserve the fully signed app before installation.
try
{
    fs::path debugPath("/tmp/AltStore-signed-debug.app");
    fs::remove_all(debugPath);
    fs::copy(app->path(), debugPath, fs::copy_options::recursive);
    odslog("DEBUG signed app copied from: " << app->path());
    odslog("DEBUG signed app preserved at: " << debugPath.string());
}
catch (const std::exception& e)
{
    odslog("DEBUG failed to preserve signed app: " << e.what());
}

		std::optional<std::set<std::string>> activeProfiles = std::nullopt;
		if (team->type() == Team::Type::Free && app->isAltStoreApp())
		{
			activeProfiles = profileIdentifiers;
		}
        
		return DeviceManager::instance()->InstallApp(app->path(), device->identifier(), activeProfiles, [](double progress) {
			odslog("Installation Progress: " << progress);
		})
		.then([app] {
			return app;
		});
    });
}

pplx::task<void> AltServerApp::EnableJIT(InstalledApp app, std::shared_ptr<Device> device)
{
	return this->PrepareDevice(device)
	.then([=] {
		return DeviceManager::instance()->StartDebugConnection(device);
	})
	.then([=](std::shared_ptr<DebugConnection> debugConnection) {
		return debugConnection->EnableUnsignedCodeExecution(app.executableName())
		.then([debugConnection]() {
				debugConnection->Disconnect();
		});
	})
	.then([=](pplx::task<void> task) {
		try {
			task.get();

			this->ShowAlert(
				"Successfully enabled JIT for " + app.name() + "!",
				"JIT will remain enabled until you quit the app. You can now disconnect " + device->name() + " from your computer."
			);
		}
        catch (std::exception& exception)
        {
            auto localizedFailure = "JIT could not be enabled for " + app.name() + ".";
            this->ShowErrorAlert(exception, localizedFailure);
        }
	});
}

void AltServerApp::ShowErrorAlert(std::exception& exception, std::string localizedFailure)
{
    try
    {
        Error& error = dynamic_cast<Error&>(exception);

        std::string title;
        std::vector<std::string> messageComponents;

        std::string separator = " ";

        try
        {
            ServerError& error = dynamic_cast<ServerError&>(exception);

            switch ((ServerErrorCode)error.code())
            {
            case ServerErrorCode::MaximumFreeAppLimitReached: 
                separator = "\n\n";
                break;

            default: break;
            }
        }
        catch (std::bad_cast)
        {
            // Ignore
        }

        if (error.localizedFailure().has_value())
        {
            // Has localized failure.

            auto errorFailure = *error.localizedFailure();

            if (error.localizedFailureReason().has_value())
            {
                // Has localized failure reason.

                auto failureReason = *error.localizedFailureReason();

                if (error.localizedDescription().compare(0, errorFailure.length(), errorFailure) == 0)
                {
                    // Localized description begins with errorFailure, so use errorFailure directly.

                    title = errorFailure;
                    messageComponents.push_back(failureReason);
                }
                else
                {
                    // Localized description is different than errorFailure, so include full description in alert.

                    title = errorFailure;
                    messageComponents.push_back(error.localizedDescription());
                }
            }
            else
            {
                // No failure reason given.

                if (error.localizedDescription().compare(0, errorFailure.length(), errorFailure) == 0)
                {
                    // No need to duplicate errorFailure in both title and message.
                    title = localizedFailure;
                    messageComponents.push_back(error.localizedDescription());
                }
                else
                {
                    title = errorFailure;
                    messageComponents.push_back(error.localizedDescription());
                }
            }
        }
        else
        {
            title = localizedFailure;
            messageComponents.push_back(error.localizedDescription());
        }

        if (error.localizedRecoverySuggestion().has_value())
        {
            auto localizedRecoverySuggestion = *error.localizedRecoverySuggestion();
            messageComponents.push_back(localizedRecoverySuggestion);
        }

        auto message = std::accumulate(messageComponents.begin(), messageComponents.end(), std::string(), [separator](auto& a, auto& b) {
            return a + (a.length() > 0 ? separator : "") + b;
        });

        this->ShowAlert(title, message);
    }
    catch (std::bad_cast)
    {
        this->ShowAlert(localizedFailure, exception.what());
    }
}

void AltServerApp::ShowInstallationNotification(std::string appName, std::string deviceName)
{
	std::stringstream ssTitle;
	ssTitle << "Installing " << appName << " to " << deviceName << "...";

	std::stringstream ssMessage;
	ssMessage << "This may take a few seconds.";

	this->ShowNotification(ssTitle.str(), ssMessage.str());
}


HWND AltServerApp::windowHandle() const
{
	return _windowHandle;
}

HINSTANCE AltServerApp::instanceHandle() const
{
	return _instanceHandle;
}


bool AltServerApp::boolValueForRegistryKey(std::string key) const
{
	return false;
}

void AltServerApp::setBoolValueForRegistryKey(bool value, std::string key)
{
	return;
}

std::string AltServerApp::serverID() const
{
	//auto serverID = GetRegistryStringValue(SERVER_ID_KEY);
	//return serverID;
	return "1234567";
}

pplx::task<std::pair<std::shared_ptr<Account>, std::shared_ptr<AppleAPISession>>> AltServerApp::Authenticate(std::string appleID, std::string password, std::shared_ptr<AnisetteData> anisetteData)
{
	auto verificationHandler = [=](void)->pplx::task<std::optional<std::string>> {
		return pplx::create_task([=]() -> std::optional<std::string> {
			std::cout << "Enter two factor code" << std::endl;
			std::string _verificationCode = "";
			std::cin >> _verificationCode;
			auto verificationCode = std::make_optional<std::string>(_verificationCode);
			_verificationCode = "";

			return verificationCode;
		});
	};

	return pplx::create_task([=]() {
		if (anisetteData == NULL)
		{
			throw ServerError(ServerErrorCode::InvalidAnisetteData);
		}

		return AppleAPI::getInstance()->Authenticate(appleID, password, anisetteData, verificationHandler);
	});
}

void AltServerApp::HandleAnisetteError(AnisetteError& error)
{
    this->ShowAlert("AnisetteData error: ", error.localizedDescription());
}

void AltServerApp::ShowNotification(std::string title, std::string message)
{
	std::cout << "Notify: " << title << std::endl << "    " << message << std::endl;
}


extern "C" int getchar();
void AltServerApp::ShowAlert(std::string title, std::string message)
{
	std::cout << "Alert: " << title << std::endl << "    " << message << std::endl;
	std::cout << "Press any key to continue..." << std::endl;
	//char a;
	//std::cin >> a;
	getchar();
}

fs::path AltServerApp::appDataDirectoryPath() const
{
	fs::path altserverDirectoryPath("./AltServerData");

	if (!fs::exists(altserverDirectoryPath))
	{
		fs::create_directory(altserverDirectoryPath);
	}

	return altserverDirectoryPath;
}

void AltServerApp::Start(HWND windowHandle, HINSTANCE instanceHandle)
{
	ConnectionManager::instance()->Start();

	// DeviceManager only needs 
	const char *isNoUSB = getenv("ALTSERVER_NO_SUBSCRIBE");
	if (!isNoUSB) {
		DeviceManager::instance()->Start();
	}
}

void AltServerApp::Stop()
{
}

fs::path AltServerApp::certificatesDirectoryPath() const
{
	auto appDataPath = this->appDataDirectoryPath();
	auto certificatesDirectoryPath = appDataPath.append("Certificates");

	if (!fs::exists(certificatesDirectoryPath))
	{
		fs::create_directory(certificatesDirectoryPath);
	}

	return certificatesDirectoryPath;
}

fs::path AltServerApp::developerDisksDirectoryPath() const
{
	auto appDataPath = this->appDataDirectoryPath();
	auto developerDisksDirectoryPath = appDataPath.append("DeveloperDiskImages");

	if (!fs::exists(developerDisksDirectoryPath))
	{
		fs::create_directory(developerDisksDirectoryPath);
	}

	return developerDisksDirectoryPath;
}