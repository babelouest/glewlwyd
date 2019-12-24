import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

import Navbar from './Navbar';
import User from './User';
import UserDelegate from './UserDelegate';
import Register from './Register';
import Session from './Session';
import PasswordModal from './PasswordModal';
import SchemePage from './SchemePage';
import Confirm from '../Modal/Confirm';
import Message from '../Modal/Message';

class App extends Component {
  constructor(props) {
    super(props);

    this.state = {
      lang: i18next.language,
      config: props.config,
      registerConfig: false,
      registerProfile: false,
      registerSchemes: {},
      curNav: "profile",
      profileList: false,
      schemeList: [],
      loggedIn: false,
      confirmModal: {
        title: "",
        message: "",
        callback: false
      },
      messageModal: {
        title: "",
        message: ""
      },
      invalidCredentialMessage: false,
      invalidDelegateMessage: false,
      tokenParsed: false
    };
    
    this.fetchProfile = this.fetchProfile.bind(this);
    this.closePasswordModal = this.closePasswordModal.bind(this);
    
    messageDispatcher.subscribe('App', (message) => {
      if (message.type === 'nav') {
        if (message.page === "password") {
          $("#passwordModal").modal({keyboard: false, show: true});
        } else if (message.page === "session") {
          this.setState({curNav: "session"});
        } else if (message.page === "profile") {
          this.setState({curNav: "profile"});
        } else {
          this.setState({curNav: message.module, module: message.page});
        }
      } else if (message.type === 'loggedIn') {
        this.setState({loggedIn: message.message}, () => {
          if (!this.state.loggedIn) {
            this.setState({profileList: false, schemeList: []});
          } else {
            this.fetchProfile();
          }
        });
      } else if (message.type === 'lang') {
        this.setState({lang: i18next.language});
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
        messageModal.message = message.message;
        this.setState({messageModal: messageModal}, () => {
          $("#messageModal").modal({keyboard: false, show: true});
        });
      } else if (message.type === 'closeConfirm') {
        $("#confirmModal").modal("hide");
      } else if (message.type === 'registration') {
        this.fetchRegistration();
      } else if (message.type === 'registrationComplete') {
        this.setState({registerProfile: false, schemeList: [],profileList: false})
        this.fetchRegistration();
      }
    });
    
    if (this.state.config) {
      if (!this.state.config.params.register) {
        this.fetchProfile();
      } else {
        this.fetchRegistration();
      }
    }
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: props.config
    });
  }
  
  fetchProfile() {
    if (!this.state.config.params.delegate) {
      apiManager.glewlwydRequest("/profile_list")
      .then((res) => {
        if (!res[0] || res[0].scope.indexOf(this.state.config.profile_scope) < 0) {
          this.setState({invalidDelegateMessage: true}, () => {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-profile-scope")});
          });
        } else {
          this.setState({profileList: res}, () => {
            apiManager.glewlwydRequest("/profile/scheme")
            .then((res) => {
              this.setState({loggedIn: true, schemeList: res, invalidDelegateMessage: false, invalidCredentialMessage: false});
            })
            .fail((error) => {
              this.setState({invalidDelegateMessage: false, invalidCredentialMessage: true}, () => {
                if (error.status === 401) {
                  messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-profile-scope")});
                } else {
                  messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
                }
              });
            });
          });
        }
      })
      .fail((error) => {
        this.setState({invalidDelegateMessage: false, invalidCredentialMessage: true}, () => {
          if (error.status === 401) {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-profile-scope")});
          } else {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
          }
        });
      });
    } else {
        apiManager.glewlwydRequest("/profile/scheme")
        .then((res) => {
          this.setState({loggedIn: true, profileList: [{username: this.state.config.params.delegate}], schemeList: res, invalidCredentialMessage: false, invalidDelegateMessage: false});
        })
        .fail((error) => {
          this.setState({invalidCredentialMessage: false, invalidDelegateMessage: true}, () => {
            if (error.status === 401) {
              messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.requires-admin-scope")});
            } else {
              messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
            }
          });
        });
    }
  }
  
  fetchRegistration() {
    apiManager.glewlwydRequest("/" + this.state.config.params.register + "/config")
    .then((config) => {
      if (!this.state.config.params.token || this.state.tokenParsed) {
        apiManager.glewlwydRequest("/" + this.state.config.params.register + "/profile")
        .then((profile) => {
          this.setState({registerProfile: profile, schemeList: config.schemes, profile: profile, profileList: [profile]}, () => {
            config.schemes.forEach(scheme => {
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
          if (err.status != 401) {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
          }
          this.setState({registerProfile: false});
        })
        .always(() => {
          this.setState({registerConfig: config});
        });
      } else {
        apiManager.glewlwydRequest("/" + this.state.config.params.register + "/verify", "POST", {token: this.state.config.params.token})
        .then(() => {
          apiManager.glewlwydRequest("/" + this.state.config.params.register + "/profile")
          .then((profile) => {
            this.setState({tokenParsed: true, registerProfile: profile, schemeList: config.schemes, profile: profile, profileList: [profile]}, () => {
              config.schemes.forEach(scheme => {
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
            if (err.status != 401) {
              messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
            }
            this.setState({registerProfile: false});
          })
          .always(() => {
            this.setState({registerConfig: config});
          });
        })
        .fail((err) => {
          if (err.status != 401) {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
          } else {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("profile.register-token-invalid")});
          }
          this.setState({registerProfile: false});
        })
        .always(() => {
          this.setState({registerConfig: config});
        });
      }
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
    });
  }

  closePasswordModal(result, data) {
    $("#passwordModal").modal("hide");
    if (result) {
      messageDispatcher.sendMessage('Notification', {type: "success", message: i18next.t("profile.password-change-success")});
    }
  }
  
	render() {
    if (this.state.config) {
      var userJsx = "", sessionJsx, invalidMessage;
      if (this.state.invalidCredentialMessage) {
        invalidMessage = <div className="alert alert-danger" role="alert">{i18next.t("profile.error-credential-message")}</div>
      } else if (this.state.invalidDelegateMessage) {
        invalidMessage = <div className="alert alert-danger" role="alert">{i18next.t("admin.error-credential-message")}</div>
      }
      if (this.state.config.params.delegate) {
        userJsx = <UserDelegate config={this.state.config} profile={(this.state.profileList?this.state.profileList[0]:false)} />
      } else if (this.state.config.params.register) {
        userJsx = <Register config={this.state.config} registerConfig={this.state.registerConfig} registerProfile={this.state.registerProfile} registerSchemes={this.state.registerSchemes} />
      } else {
        userJsx = <User config={this.state.config} profile={(this.state.profileList?this.state.profileList[0]:false)} pattern={this.state.config?this.state.config.pattern.user:false}/>
      }
      return (
        <div aria-live="polite" aria-atomic="true" style={{position: "relative", minHeight: "200px"}}>
          <div className="card center" id="userCard" tabIndex="-1" role="dialog" style={{marginTop: 20 + 'px', marginBottom: 20 + 'px'}}>
            <div className="card-header">
              <Navbar active={this.state.curNav} config={this.state.config} loggedIn={this.state.loggedIn} schemeList={this.state.schemeList} profileList={this.state.profileList}/>
            </div>
            {invalidMessage}
            <div className="card-body">
              <div id="carouselBody" className="carousel slide" data-ride="carousel">
                <div className="carousel-inner">
                  <div className={"carousel-item" + (this.state.curNav==="profile"?" active":"")}>
                    {userJsx}
                  </div>
                  <div className={"carousel-item" + (this.state.curNav==="session"?" active":"")}>
                    <Session config={this.state.config} profile={(this.state.profileList?this.state.profileList[0]:false)} loggedIn={this.state.loggedIn} />
                  </div>
                  <div className={"carousel-item" + (this.state.curNav!=="profile"&&this.state.curNav!=="session"?" active":"")}>
                    <SchemePage config={this.state.config} module={this.state.curNav} name={this.state.module} profile={(this.state.profileList?this.state.profileList[0]:false)}/>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <Notification/>
          <PasswordModal config={this.state.config} callback={this.closePasswordModal}/>
          <Confirm title={this.state.confirmModal.title} message={this.state.confirmModal.message} callback={this.state.confirmModal.callback} />
          <Message title={this.state.messageModal.title} message={this.state.messageModal.message} />
        </div>
      );
    } else {
      return (
        <div aria-live="polite" aria-atomic="true" style={{position: "relative", minHeight: "200px"}}>
          <div className="card center" id="userCard" tabIndex="-1" role="dialog" style={{marginTop: 20 + 'px', marginBottom: 20 + 'px'}}>
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
