import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

import Navbar from './Navbar';
import User from './User';
import UserDelegate from './UserDelegate';
import UserResetCredentials from './UserResetCredentials';
import Register from './Register';
import Session from './Session';
import Password from './Password';
import SchemePage from './SchemePage';

import Confirm from '../Modal/Confirm';
import Message from '../Modal/Message';
import Edit from '../Modal/Edit';

class App extends Component {
  constructor(props) {
    super(props);

    this.state = {
      lang: i18next.language,
      config: props.config,
      registerPlugin: [],
      registerConfig: false,
      registerProfile: false,
      registerSchemes: {},
      schemeHighlight: {},
      registering: false,
      registerValid: true,
      curNav: "profile",
      profileList: false,
      profileUpdate: false,
      schemeList: [],
      loggedIn: false,
      confirmModal: {
        title: "",
        message: "",
        callback: false
      },
      messageModal: {
        title: "",
        label: "",
        message: ""
      },
      editModal: {
        title: "",
        message: "",
        value: "",
        placeHolder: "",
        callback: false
      },
      plugins: {
        oauth2: {
        },
        oidc: {
        }
      },
      sessionList: [],
      clientGrantList: [],
      invalidCredentialMessage: false,
      invalidDelegateMessage: false,
      tokenParsed: false,
      registerDefaultLang: false,
      updateEmail: [],
      updateEmailModule: false,
      register: false,
      schemePrefix: ((props.config && props.config.params.register)?"/" + props.config.params.register + "/profile":"/profile"),
      resetCredentials: 0,
      cibaList: []
    };

    this.fetchProfile = this.fetchProfile.bind(this);
    this.updateEmailCallback = this.updateEmailCallback.bind(this);
    this.refreshSession = this.refreshSession.bind(this);
    this.refreshClientGrant = this.refreshClientGrant.bind(this);

    messageDispatcher.subscribe('App', (message) => {
      if (message.type === 'nav') {
        if (message.page === "password") {
          this.setState({curNav: "password"});
        } else if (message.page === "session") {
          this.setState({curNav: "session"});
        } else if (message.page === "profile") {
          this.setState({curNav: "profile"});
        } else if (message.page === "resetCredentialsCode") {
          this.setState({curNav: "resetCredentialsCode"});
        } else {
          this.setState({curNav: message.module, module: message.page});
        }
      } else if (message.type === 'loggedIn') {
        this.setState({loggedIn: message.loggedIn, curNav: "profile"}, () => {
          this.fetchProfile();
        });
      } else if (message.type === 'lang') {
        this.setState({lang: i18next.language}, () => {
          if (this.state.config.params.register && this.state.registerConfig.languages.length) {
            this.state.registerConfig.languages.forEach((lang) => {
              if (lang === this.state.lang) {
                this.setState({registerDefaultLang: lang});
              }
            });
          }
        });
      } else if (message.type === 'profile') {
        this.fetchProfile();
      } else if (message.type === 'confirm') {
        var confirmModal = this.state.confirmModal;
        confirmModal.title = message.title;
        confirmModal.message = message.message;
        confirmModal.callback = message.callback;
        this.setState({confirmModal: confirmModal}, () => {
          $("#confirmModal").modal({keyboard: false, show: true});
        });
      } else if (message.type === 'message') {
        var messageModal = this.state.messageModal;
        messageModal.title = message.title;
        messageModal.label = message.label;
        messageModal.message = message.message;
        this.setState({messageModal: messageModal}, () => {
          $("#messageModal").modal({keyboard: false, show: true});
        });
      } else if (message.type === 'closeConfirm') {
        $("#confirmModal").modal("hide");
      } else if (message.type === 'registration') {
        if (this.state.config.params.register) {
          this.setState({registerProfile: false, schemeList: [], profileList: false}, () => {
            this.fetchRegistration();
          });
        }
      } else if (message.type === 'registrationComplete') {
        if (!this.state.config.params.register) {
          this.setState({registerProfile: false, schemeList: [], profileList: false, registering: false}, () => {
            this.fetchRegistration();
          });
        } else {
          this.setState({registerProfile: false, schemeList: [], profileList: false, registering: false});
        }
      } else if (message.type === 'updateEmailAvailable') {
        var updateEmail = this.state.updateEmail;
        if (message.module) {
          updateEmail.push(message.module);
        }
        this.setState({updateEmail: updateEmail, register: true});
      } else if (message.type === 'updateEmail') {
        if (message.module) {
          var editModal = {
            title: i18next.t("profile.update-email-modal-title"),
            message : i18next.t("profile.update-email-modal-message"),
            value : "",
            placeHolder : i18next.t("profile.update-email-modal-ph"),
            callback : this.updateEmailCallback,
          }
          this.setState({editModal: editModal, updateEmailModule: message.module}, () => {
            $("#editModal").modal({keyboard: false, show: true});
          });
        }
      } else if (message.type === 'refreshSession') {
        this.refreshSession();
      } else if (message.type === 'refreshClientGrant') {
        this.refreshClientGrant();
      }
    });

    if (this.state.config) {
      this.getRegisterConfig();
      if (this.state.config.params.updateEmail) {
        this.updateEmailVerifyToken(this.state.config.params.updateEmail, this.state.config.params.token)
        .then(() => {
          messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("profile.update-email-success")});
          this.fetchProfile();
        });
      } else if (this.state.config.params.resetCredentials) {
        if (this.state.config.register) {
          if (this.state.config.params.token) {
            apiManager.glewlwydRequest("/" + this.state.config.params.resetCredentials + "/reset-credentials-email/" + encodeURI(this.state.config.params.token), "PUT")
            .then(() => {
              this.getResetCredentialsConfig();
            })
            .fail((err) => {
              if (err.status === 403) {
                this.setState({resetCredentials: -1});
                messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.reset-credentials-email-token-error")});
              } else {
                messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
              }
            });
          } else {
            this.getResetCredentialsConfig();
          }
        }
      } else if (!this.state.config.params.register) {
        this.fetchProfile();
      }
    }
  }

  getRegisterConfig() {
    if (this.state.config.register) {
      this.state.config.register.forEach((register, index) => {
        apiManager.glewlwydRequest("/" + register.name + "/config")
        .then((config) => {
          var registerPlugin = this.state.registerPlugin;
          config.name = register.name;
          registerPlugin.push(config);
          this.setState({registerPlugin: registerPlugin}, () => {
            if (this.state.config.params.register) {
              this.fetchRegistration();
            }
            if (config["update-email"]) {
              var updateEmail = this.state.updateEmail;
              updateEmail.push(register.name);
              this.setState({updateEmail: updateEmail});
            }
          });
        })
        .fail((err) => {
          this.setState({registerValid: false, registering: false}, () => {
            if (err.status === 404) {
              messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.register-invalid-url")});
            } else {
              messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
            }
          });
        });
      });
    }
  }

  getResetCredentialsConfig() {
    apiManager.glewlwydRequest("/" + this.state.config.params.resetCredentials + "/reset-credentials/profile/")
    .then((profile) => {
      this.setState({profileList: [profile.user], loggedIn: true, schemeList: profile.scheme, schemePrefix: "/" + this.state.config.params.resetCredentials + "/reset-credentials/profile", resetCredentials: 1});
    })
    .fail((err) => {
      if (err.status === 401) {
        this.setState({invalidCredentialMessage: true, resetCredentials: -1});
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-profile-scope")});
      } else {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      }
    });
  }

  fetchProfile() {
    if (!this.state.config.params.delegate) {
      apiManager.glewlwydRequest("/profile_list")
      .then((res) => {
        this.setState({profileList: res}, () => {
          if (!res[0] || res[0].scope.indexOf(this.state.config.profile_scope) < 0) {
            this.setState({loggedIn: false, schemeList: [], invalidDelegateMessage: false, invalidCredentialMessage: true, profileUpdate: false}, () => {
              messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-profile-scope")});
            });
          } else {
            apiManager.glewlwydRequest("/profile/scheme")
            .then((schemeList) => {
              this.setState({loggedIn: true, schemeList: schemeList, invalidDelegateMessage: false, invalidCredentialMessage: false, profileUpdate: true}, () => {
                if (this.state.config.params.scheme_name) {
                  schemeList.forEach((scheme) => {
                    if (scheme.name === this.state.config.params.scheme_name) {
                      messageDispatcher.sendMessage('Nav', {type: scheme.module, page: scheme.name});
                    }
                  });
                }
              });
              this.refreshSession();
              this.refreshClientGrant();
            })
            .fail((error) => {
              this.setState({loggedIn: false, schemeList: [], invalidDelegateMessage: false, invalidCredentialMessage: true, profileUpdate: false}, () => {
                if (error.status === 401) {
                  messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-profile-scope")});
                } else {
                  messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
                }
              });
            });
          }
        });
      })
      .fail((error) => {
        this.setState({loggedIn: false, profileList: false, schemeList: [], invalidDelegateMessage: false, invalidCredentialMessage: true}, () => {
          if (error.status === 401) {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-profile-scope")});
          } else {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
          }
        });
      });
    } else {
      apiManager.glewlwydRequest("/profile/scheme")
      .then((schemeList) => {
        this.setState({loggedIn: true, profileList: [{username: this.state.config.params.delegate}], schemeList: schemeList, invalidCredentialMessage: false, invalidDelegateMessage: false}, () => {
          if (this.state.config.params.scheme_name) {
            schemeList.forEach((scheme) => {
              if (scheme.name === this.state.config.params.scheme_name) {
                messageDispatcher.sendMessage('Nav', {type: scheme.module, page: scheme.name});
              }
            });
          }
        });
      })
      .fail((error) => {
        this.setState({invalidCredentialMessage: false, invalidDelegateMessage: true}, () => {
          if (error.status === 401) {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-profile-scope")});
          } else {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
          }
        });
      });
    }
  }

  refreshSession() {
    apiManager.glewlwydRequest("/profile/session")
    .then((res) => {
      this.setState({sessionList: res}, () => {
        apiManager.glewlwydRequest("/profile/plugin")
        .then((res) => {
          res.forEach((plugin) => {
            if (plugin.module === "oauth2-glewlwyd") {
              apiManager.glewlwydRequestSub("/" + plugin.name + "/profile/token" + (this.state.config.params.delegate?"?impersonate="+this.state.config.params.delegate:""))
              .then((resPlugin) => {
                var plugins = this.state.plugins;
                plugins.oauth2[plugin.name] = resPlugin;
                this.setState({plugins: plugins});
              })
              .fail((err) => {
                messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
              });
            } else if (plugin.module === "oidc") {
              apiManager.glewlwydRequestSub("/" + plugin.name + "/token" + (this.state.config.params.delegate?"?impersonate="+this.state.config.params.delegate:""))
              .then((resPlugin) => {
                var plugins = this.state.plugins;
                plugins.oidc[plugin.name] = resPlugin;
                this.setState({plugins: plugins});
              })
              .fail((err) => {
                messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
              });
              apiManager.glewlwydRequest("/" + plugin.name + "/ciba_user_list")
              .then((cibaList) => {
                this.setState({cibaList: cibaList});
              })
              .fail((err) => {
                if (err.status !== 404) {
                  messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
                }
              });
            }
          });
          messageDispatcher.sendMessage('App', {type: "sessionComplete"});
        })
        .fail((err) => {
          if (err.status === 401) {
            this.setState({invalidCredentialMessage: true});
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-profile-scope")});
          } else {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
          }
        });
      });
    })
    .fail((err) => {
      if (err.status === 401) {
        this.setState({invalidCredentialMessage: true, loggedIn: false, sessionList: [], clientGrantList: [], cibaList: []});
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-profile-scope")});
      } else {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      }
    });
  }
  
  refreshClientGrant() {
    apiManager.glewlwydRequest("/profile/grant")
    .then((res) => {
      this.setState({clientGrantList: res});
    })
    .fail((err) => {
      if (err.status === 401) {
        this.setState({invalidCredentialMessage: true});
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-profile-scope")});
      } else {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      }
    });
  }

  fetchRegistration() {
    this.state.registerPlugin.forEach((registerPlugin) => {
      if (registerPlugin.registration) {
        var defaultLang = false;
        if (this.state.lang) {
          if (registerPlugin.registration.languages.length) {
            registerPlugin.registration.languages.forEach((lang) => {
              if (lang === this.state.lang) {
                defaultLang = this.state.lang;
              }
            });
          }
        }
        if (!defaultLang && registerPlugin.registration.languages.length) {
          defaultLang = registerPlugin.registration.languages[0];
        }
        this.setState({registerValid: true, registerConfig: registerPlugin.registration, registerDefaultLang: defaultLang}, () => {
          if (!this.state.config.params.token || this.state.tokenParsed) {
            apiManager.glewlwydRequest("/" + this.state.config.params.register + "/profile")
            .then((profile) => {
              this.setState({registerProfile: profile, schemeList: registerPlugin.registration.schemes, profile: profile, profileList: [profile], registering: true}, () => {
                registerPlugin.registration.schemes.forEach(scheme => {
                  apiManager.glewlwydRequest("/" + this.state.config.params.register + "/profile/scheme/register/canuse", "PUT", {username: profile.username, scheme_type: scheme.module, scheme_name: scheme.name})
                  .then(() => {
                    var registerSchemes = this.state.registerSchemes;
                    var schemeHighlight = this.state.schemeHighlight;
                    schemeHighlight[scheme.name] = false;
                    registerSchemes[scheme.name] = true;
                    this.setState({registerSchemes: registerSchemes, schemeHighlight: schemeHighlight});
                  })
                  .fail(() => {
                    var registerSchemes = this.state.registerSchemes;
                    var schemeHighlight = this.state.schemeHighlight;
                    registerSchemes[scheme.name] = false;
                    if (scheme.register == "always") {
                      schemeHighlight[scheme.name] = true;
                    }
                    this.setState({registerSchemes: registerSchemes, schemeHighlight: schemeHighlight});
                  });
                });
              });
            })
            .fail((err) => {
              if (err.status != 401) {
                messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
              }
              this.setState({registerProfile: false, registering: false});
            });
          } else {
            apiManager.glewlwydRequest("/" + this.state.config.params.register + "/verify", "POST", {token: this.state.config.params.token})
            .then(() => {
              apiManager.glewlwydRequest("/" + this.state.config.params.register + "/profile")
              .then((profile) => {
                this.setState({tokenParsed: true, registerProfile: profile, schemeList: registerPlugin.schemes, profile: profile, profileList: [profile], registering: true}, () => {
                  registerPlugin.registration.schemes.forEach(scheme => {
                    apiManager.glewlwydRequest("/" + this.state.config.params.register + "/profile/scheme/register/canuse", "PUT", {username: profile.username, scheme_type: scheme.module, scheme_name: scheme.name})
                    .then(() => {
                      var registerSchemes = this.state.registerSchemes;
                      registerSchemes[scheme.name] = true;
                      this.setState({registerSchemes: registerSchemes});
                    })
                    .fail(() => {
                      var registerSchemes = this.state.registerSchemes;
                      registerSchemes[scheme.name] = false;
                      this.setState({registerSchemes: registerSchemes});
                    });
                  });
                });
              })
              .fail((err) => {
                if (err.status !== 401) {
                  messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
                }
                this.setState({registerProfile: false, registering: false, invalidCredentialMessage: true});
              });
            })
            .fail((err) => {
              if (err.status !== 401) {
                messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
              } else {
                messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.register-token-invalid")});
              }
              this.setState({registerProfile: false, registering: false});
            });
          }
        });
      }
      if (registerPlugin["update-email"]) {
        var updateEmail = this.state.updateEmail;
        updateEmail.push(this.state.config.params.register);
        this.setState({updateEmail: updateEmail});
      }
    });
  }

  updateEmailVerifyToken(module, token) {
    return apiManager.glewlwydRequest("/" + module + "/update-email/" + encodeURIComponent(token), "PUT")
    .fail((err) => {
      if (err.status === 401) {
        this.setState({invalidCredentialMessage: true});
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-profile-scope")});
      } else {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      }
    });
  }

  showPasswordChangeNotification(result, data) {
    if (result) {
      messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("profile.password-change-success")});
    }
  }

  updateEmailCallback(result, value) {
    $("#editModal").modal("hide");
    if (result) {
      apiManager.glewlwydRequest("/" + this.state.updateEmailModule + "/update-email", "POST", {email: value})
      .then((res) => {
        var messageModal = {
          title: i18next.t("profile.update-email-modal-title"),
          message: [i18next.t("profile.update-email-modal-complete-message", {email: value})]
        };
        this.setState({messageModal: messageModal}, () => {
          $("#messageModal").modal({keyboard: false, show: true});
        });
      })
      .fail((err) => {
        if (err.status === 401) {
          this.setState({invalidCredentialMessage: true});
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-profile-scope")});
        } else {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
        }
      });
    }
  }

	render() {
    if (this.state.config) {
      var userJsx = "", invalidMessage, cibaListJsx = [];
      if (this.state.invalidCredentialMessage) {
        invalidMessage = <div className="alert alert-danger" role="alert">{i18next.t("profile.error-credential-message")}</div>
      } else if (this.state.invalidDelegateMessage) {
        invalidMessage = <div className="alert alert-danger" role="alert">{i18next.t("admin.error-credential-message")}</div>
      }
      if (this.state.config.params.delegate) {
        userJsx = <UserDelegate config={this.state.config} profile={(this.state.profileList[0]||false)} />
      } else if (this.state.config.params.register) {
        userJsx = <Register config={this.state.config} registerConfig={this.state.registerConfig} registerProfile={this.state.registerProfile} registerSchemes={this.state.registerSchemes} registerValid={this.state.registerValid} registerDefaultLang={this.state.registerDefaultLang} />
      } else if (this.state.config.params.resetCredentials) {
        userJsx = <UserResetCredentials config={this.state.config} profile={(this.state.profileList[0]||false)} status={this.state.resetCredentials} />
      } else {
        userJsx = <User config={this.state.config} profile={(this.state.profileList[0]||false)} pattern={this.state.config?this.state.config.pattern.user:false} profileUpdate={this.state.profileUpdate} loggedIn={this.state.loggedIn} updateEmail={this.state.updateEmail}/>
      }
      this.state.cibaList.forEach((ciba, index) => {
        var bindingMessage;
        if (ciba.binding_message) {
          bindingMessage = <div>{ciba.binding_message}</div>;
        }
        cibaListJsx.push(
          <div className="alert alert-info" role="alert" key={index}>
            {i18next.t("profile.ciba-connect-message", {client: ciba.client_name||ciba.client_id})}
            {bindingMessage}
            <div>
              <a href={ciba.connect_uri}>{i18next.t("profile.ciba-connect-link")}</a>
            </div>
            <div>
              <a href={ciba.cancel_uri}>{i18next.t("profile.ciba-cancel-link")}</a>
            </div>
          </div>
        );
      });
      return (
        <div aria-live="polite" aria-atomic="true" className="glwd-container">
          <div className="card center glwd-card" id="userCard" tabIndex="-1" role="dialog">
            <div className="card-header">
              <Navbar active={this.state.curNav}
                      config={this.state.config}
                      loggedIn={this.state.loggedIn}
                      schemeList={this.state.schemeList}
                      profileList={this.state.profileList}
                      dataHighlight={!this.state.registerProfile.password_set}
                      schemeHighlight={this.state.schemeHighlight}
                      registering={this.state.registering}/>
            </div>
            {invalidMessage}
            {cibaListJsx}
            <div className="card-body">
              <div id="carouselBody" className="carousel slide" data-ride="carousel">
                <div className="carousel-inner">
                  <div className={"carousel-item" + (this.state.curNav==="profile"?" active":"")}>
                    {userJsx}
                  </div>
                  <div className={"carousel-item" + (this.state.curNav==="session"?" active":"")}>
                    <Session config={this.state.config} plugins={this.state.plugins} sessionList={this.state.sessionList} clientGrantList={this.state.clientGrantList}/>
                  </div>
                  <div className={"carousel-item" + (this.state.curNav==="password"?" active":"")}>
                    <Password config={this.state.config}
                              profile={(this.state.profileList[0]||false)}
                              loggedIn={this.state.loggedIn}
                              callback={this.showPasswordChangeNotification}
                              registerPlugin={this.state.registerPlugin} />
                  </div>
                  <div className={"carousel-item" + (this.state.curNav!=="profile"&&this.state.curNav!=="session"&&this.state.curNav!=="password"?" active":"")}>
                    <SchemePage config={this.state.config}
                                module={this.state.curNav}
                                name={this.state.module}
                                profile={(this.state.profileList[0]||false)}
                                schemePrefix={this.state.schemePrefix}/>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <Notification loggedIn={this.state.loggedIn||this.state.config.params.register}/>
          <Confirm title={this.state.confirmModal.title} message={this.state.confirmModal.message} callback={this.state.confirmModal.callback} />
          <Message title={this.state.messageModal.title} label={this.state.messageModal.label} message={this.state.messageModal.message} />
          <Edit title={this.state.editModal.title}
                message={this.state.editModal.message}
                value={this.state.editModal.value}
                placeholder={this.state.editModal.placeHolder}
                callback={this.state.editModal.callback} />
        </div>
      );
    } else {
      return (
        <div aria-live="polite" aria-atomic="true" className="glwd-container">
          <div className="card center glwd-card" id="userCard" tabIndex="-1" role="dialog">
            <div className="card-header">
              <h4>
                <span className="badge badge-danger">
                  {i18next.t("error-api-connect")}
                </span>
              </h4>
            </div>
          </div>
        </div>
      );
    }
	}
}

export default App;
