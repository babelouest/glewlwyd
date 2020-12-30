import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';
import Buttons from './Buttons';
import Body from './Body';
import PasswordForm from './PasswordForm';
import NoPasswordForm from './NoPasswordForm';
import SelectAccount from './SelectAccount';
import EndSession from './EndSession';
import SessionClosed from './SessionClosed';
import DeviceAuth from './DeviceAuth';
import ResetCredentials from './ResetCredentials';

import Message from '../Modal/Message';

class App extends Component {
  constructor(props) {
    super(props);
    this.state = {
      newUser: false,
      userList: [],
      currentUser: false,
      config: props.config,
      loaded: false,
      lang: i18next.language,
      scope: [],
      mustRegisterScheme: false,
      scheme: props.config.params.scheme,
      schemeListRequired: false,
      passwordRequired: false,
      client: false,
      showGrant: true,
      showGrantAsterisk: false,
      showAuthDetailsAsterisk: false,
      canContinue: false,
      prompt: props.config.params.prompt,
      refresh_login: props.config.params.refresh_login,
      forceShowGrant: false,
      selectAccount: false,
      endSession: false,
      sessionClosed: false,
      deviceAuth: false,
      login_hint: props.config.params.login_hint||"",
      errorScopesUnavailable: false,
      infoSomeScopeUnavailable: false,
      errorScheme: false,
      registration: [],
      resetCredentials: [],
      resetCredentialsShow: false,
      authDetails: [],
      messageModal: {
        title: "",
        label: "",
        message: ""
      }
    };

    this.initProfile = this.initProfile.bind(this);
    this.checkClientScope = this.checkClientScope.bind(this);
    this.checkScopeScheme = this.checkScopeScheme.bind(this);
    this.changeLang = this.changeLang.bind(this);
    this.parseSchemes = this.parseSchemes.bind(this);

    if (this.state.config) {
      this.initProfile(true);
    }

    messageDispatcher.subscribe('App', (message) => {
      if (message.type === "InitProfile") {
        this.initProfile(false);
      } else if (message.type === "loginSuccess") {
        this.setState({selectAccount: false, newUser: false, refresh_login: false, prompt: false, resetCredentialsShow: false}, () => {
          this.initProfile(false);
        });
      } else if (message.type === "NewUser") {
        this.setState({selectAccount: false, newUser: true, currentUser: false, scheme: this.state.config.params.scheme, resetCredentialsShow: false}, () => {
        });
      } else if (message.type === "GrantComplete") {
        this.setState({selectAccount: false, showGrant: false, prompt: false, forceShowGrant: false, resetCredentialsShow: false}, () => {
          this.initProfile(false);
        });
      } else if (message.type === "SelectAccount") {
        this.setState({selectAccount: true, newUser: false}, () => {
          this.initProfile(false);
        });
      } else if (message.type === "SelectAccountComplete") {
        this.setState({selectAccount: false, prompt: false}, () => {
          this.initProfile(false);
        });
      } else if (message.type === "ToggleGrant") {
        this.setState({showGrant: !this.state.showGrant});
      } else if (message.type === "newUserScheme") {
        this.setState({scheme: message.scheme});
      } else if (message.type === "SessionClosed") {
        this.setState({endSession: false, sessionClosed: true});
      } else if (message.type === "ResetCredentials") {
        this.setState({selectAccount: false, newUser: false, refresh_login: false, prompt: false, resetCredentialsShow: true});
      } else if (message.type === 'message') {
        var messageModal = this.state.messageModal;
        messageModal.title = message.title;
        messageModal.label = message.label;
        messageModal.message = message.message;
        this.setState({messageModal: messageModal}, () => {
          $("#messageModal").modal({keyboard: false, show: true});
        });
      }
    });
  }

  initProfile(checkPrompt) {
    if (this.state.config.register) {
      var registration = [];
      var resetCredentials = [];
      this.state.config.register.forEach((register, index) => {
        apiManager.glewlwydRequest("/" + register.name + "/config")
        .then((config) => {
          if (config.registration) {
            registration.push({name: register.name, message: register.message});
          }
          if (config["reset-credentials"].email || config["reset-credentials"].code) {
            resetCredentials.push({name: register.name, message: register["reset-credentials-message"], email: config["reset-credentials"].email, code: config["reset-credentials"].code});
          }
          this.setState({registration: registration, resetCredentials: resetCredentials});
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
    apiManager.glewlwydRequest("/profile_list")
    .then((res) => {
      var newState = {};
      if (res.length) {
        newState.currentUser = res[0];
        newState.login_hint = res[0].username;
        newState.errorScopesUnavailable = !this.userHasScope(res[0], this.state.config.params.scope);
      }
      newState.userList = res;
      newState.loaded = true;
      if (checkPrompt) {
        if (this.state.prompt === "login") {
          newState.currentUser = false;
          newState.newUser = true;
        } else if (this.state.prompt === "consent") {
          newState.forceShowGrant = true;
        } else if (this.state.prompt === "select_account") {
          newState.selectAccount = true;
        } else if (this.state.prompt === "end_session") {
          newState.endSession = true;
          newState.newUser = false;
          newState.currentUser = false;
        } else if (this.state.prompt && this.state.prompt.substring(0, 6) === "device") {
          newState.deviceAuth = true;
        } else {
          newState.newUser = false;
        }
      }
      this.setState(newState, () => {
        if (this.state.config.params.client_id && this.state.config.params.scope) {
          this.checkClientScope(this.state.config.params.client_id, this.state.config.params.scope)
          .then(() => {
            this.checkAuthorizationDetails(this.state.config.params.authorization_details);
          });
        } else if (this.state.config.params.scope) {
          this.checkScopeScheme(this.state.config.params.scope);
        } else {
          this.setState({showGrantAsterisk: false});
        }
      });
    })
    .fail((error) => {
      if (error.status != 401) {
        messageDispatcher.sendMessage('Notification', {type: "warning", message: i18next.t("error-api-connect")});
      }
      if (this.state.prompt === "device") {
        this.setState({deviceAuth: true, currentUser: false, userList: [], loaded: true, scheme: this.state.config.params.scheme});
      } else {
        this.setState({newUser: (!!this.state.config.params.callback_url && !!this.state.config.params.scope), showGrant: false, currentUser: false, userList: [], loaded: true, scheme: this.state.config.params.scheme});
      }
    });
  }

  checkClientScope(clientId, scopeList) {
    return apiManager.glewlwydRequest("/auth/grant/" + encodeURIComponent(clientId) + "/" + encodeURIComponent(scopeList))
    .then((res) => {
      var scopeGranted = [];
      var showGrant = true;
      var showGrantAsterisk = false;
      var callback_url = decodeURIComponent(this.state.config.params.callback_url);
      if (callback_url) {
        const urlParams = new URLSearchParams(callback_url);
        res.client.redirect_uri = urlParams.get("redirect_uri");
      }
      if (res.scope.length) {
        var infoSomeScopeUnavailable = (scopeList.split(" ").length > res.scope.length);
        if (scopeList === "openid") {
          showGrant = false || this.state.forceShowGrant;
          scopeGranted.push("openid");
        } else {
          res.scope.forEach((scope) => {
            if (scope.name === "openid") {
              scope.granted = true;
            }
            if (scope.granted) {
              if (scope.name !== "openid") {
                showGrant = false || this.state.forceShowGrant;
              }
              scopeGranted.push(scope.name);
            } else {
              showGrantAsterisk = true;
            }
          });
        }
        if (scopeGranted.length) {
          return apiManager.glewlwydRequest("/auth/scheme/?scope=" + encodeURIComponent(scopeGranted.join(" ")))
          .then((schemeRes) => {
            return this.setState({client: res.client, 
                           scope: res.scope, 
                           scheme: schemeRes, 
                           showGrant: showGrant, 
                           showGrantAsterisk: showGrantAsterisk, 
                           infoSomeScopeUnavailable: infoSomeScopeUnavailable, 
                           errorScopesUnavailable: false}, () => {
              return this.parseSchemes();
            });
          })
          .fail((error) => {
            messageDispatcher.sendMessage('Notification', {type: "warning", message: i18next.t("login.error-scheme-scope-api")});
          });
        } else {
          return this.setState({client: res.client, 
                         scope: res.scope, 
                         showGrant: true, 
                         showGrantAsterisk: true, 
                         errorScopesUnavailable: false, 
                         infoSomeScopeUnavailable: infoSomeScopeUnavailable});
        }
      } else {
        return this.setState({errorScopesUnavailable: true, infoSomeScopeUnavailable: false});
      }
    })
    .fail((error) => {
      if (error.status === 404) {
        messageDispatcher.sendMessage('Notification', {type: "warning", message: i18next.t("login.error-scheme-scope-unavailable")});
      } else {
        messageDispatcher.sendMessage('Notification', {type: "warning", message: i18next.t("login.error-grant-api")});
      }
    });
  }

  checkScopeScheme(scopeList) {
    apiManager.glewlwydRequest("/auth/scheme/?scope=" + scopeList)
    .then((schemeRes) => {
      this.setState({scheme: schemeRes, showGrant: false, showGrantAsterisk: false}, () => {
        this.parseSchemes();
      });
    })
    .fail((error) => {
      if (error.status === 404) {
        messageDispatcher.sendMessage('Notification', {type: "warning", message: i18next.t("login.error-scheme-scope-unavailable")});
      } else {
        messageDispatcher.sendMessage('Notification', {type: "warning", message: i18next.t("login.error-scheme-scope-api")});
      }
    });
  }
  
  checkAuthorizationDetails(authorization_details) {
    if (authorization_details) {
      var showAuthDetailsAsterisk = false;
      var authDetails = [];
      authorization_details.split(",").forEach(authName => {
        apiManager.glewlwydRequest("/" + this.state.config.params.plugin + "/rar/" + this.state.config.params.client_id + "/" +authName)
        .then((curDetails) => {
          if (curDetails.scopes && curDetails.scopes.length) {
            var enabled = false;
            this.state.scope.forEach((scope) => {
              if (curDetails.scopes.indexOf(scope.name) > -1) {
                enabled = true;
              }
            });
            curDetails.enabled = enabled;
          } else {
            curDetails.enabled = true;
          }
          authDetails.push(curDetails);
          this.setState({authDetails: authDetails, showAuthDetailsAsterisk: (showAuthDetailsAsterisk | !curDetails.consent)});
        })
        .fail((error) => {
          if (error.status !== 404) {
            messageDispatcher.sendMessage('Notification', {type: "warning", message: i18next.t("login.error-scheme-scope-api")});
          }
        });
      });
    }
  }

  parseSchemes() {
    var canContinue = !!this.state.config.params.callback_url;
    var passwordRequired = false;
    var schemeListRequired = false;
    var scheme = false;
    var mustRegisterScheme = false;
    for (var scopeName in this.state.scheme) {
      if (canContinue) {
        var scope = this.state.scheme[scopeName];
        if (scope.available && scope.password_required && !scope.password_authenticated) {
          canContinue = false;
          passwordRequired = true;
          schemeListRequired = false;
          scheme = false;
          break;
        } else if (!schemeListRequired && canContinue) {
          for (var groupName in scope.schemes) {
            var group = scope.schemes[groupName];
            var schemeRequired = scope.scheme_required[groupName];
            var groupSchemeAuthenticated = 0;
            schemeListRequired = group;
            group.forEach((curScheme) => {
              mustRegisterScheme = false;
              if (curScheme.scheme_authenticated) {
                groupSchemeAuthenticated++;
                scheme = false;
              } else if ((!scheme || scheme.scheme_last_login < curScheme.scheme_last_login) && curScheme.scheme_registered) {
                scheme = curScheme;
              } else if (!curScheme.scheme_registered && !scheme) {
                mustRegisterScheme = true;
              }
            });
            if (groupSchemeAuthenticated < schemeRequired) {
              canContinue = false;
              break;
            } else {
              schemeListRequired = false;
            }
          }
        }
      }
    }
    if (!passwordRequired && this.state.refresh_login) {
      passwordRequired = true;
    }
    if (canContinue) {
      scheme = false;
    }
    return this.setState({canContinue: canContinue, 
                   passwordRequired: passwordRequired, 
                   schemeListRequired: schemeListRequired, 
                   scheme: scheme, 
                   errorScheme: (!scheme && !canContinue), 
                   mustRegisterScheme: mustRegisterScheme});
  }

  changeLang(e, lang) {
    i18next.changeLanguage(lang)
    .then(() => {
      this.setState({lang: lang});
    });
  }
  
  userHasScope(user, scope_list) {
    var hasScope = false;
    if (scope_list) {
      scope_list.split(" ").forEach(scope => {
        if (user.scope.indexOf(scope) > -1) {
          hasScope = true;
        }
      });
    }
    return hasScope;
  }

	render() {
    if (this.state.config) {
      var body = "", message, scopeUnavailable;
      if (this.state.loaded) {
        if (this.state.resetCredentialsShow) {
          body = <ResetCredentials config={this.state.config} resetCredentials={this.state.resetCredentials}/>;
        } else if (this.state.endSession) {
          body = <EndSession config={this.state.config} userList={this.state.userList} currentUser={this.state.currentUser}/>;
        } else if (this.state.sessionClosed) {
          body = <SessionClosed config={this.state.config}/>;
        } else if (this.state.deviceAuth) {
          body = <DeviceAuth config={this.state.config} userList={this.state.userList} currentUser={this.state.currentUser}/>;
        } else {
          if (this.state.mustRegisterScheme && !this.state.errorScopesUnavailable) {
            message = <div className="alert alert-warning" role="alert">{i18next.t("login.warning-not-registered-scheme")}</div>
          } else if (this.state.errorScheme && !this.state.errorScopesUnavailable) {
            message = <div className="alert alert-warning" role="alert">{i18next.t("login.warning-error-scheme")}</div>
          } else {
            var noCallback, noScope;
            if (!this.state.config.params.callback_url) {
              noCallback = <div className="alert alert-warning" role="alert">{i18next.t("login.warning-no-callback-url")}</div>;
            }
            if (!this.state.config.params.scope) {
              noScope = <div className="alert alert-warning" role="alert">{i18next.t("login.warning-no-scope")}</div>;
            }
            message = <div>{noCallback}{noScope}</div>;
          }
          if ((this.state.newUser || this.state.passwordRequired)) {
            if (!this.state.scheme) {
              body = <PasswordForm config={this.state.config} 
                                   username={this.state.login_hint} 
                                   currentUser={this.state.currentUser} 
                                   userList={this.state.userList} 
                                   callbackInitProfile={this.initProfile}/>;
            } else {
              body = <NoPasswordForm config={this.state.config} 
                                     username={this.state.login_hint} 
                                     userList={this.state.userList} 
                                     callbackInitProfile={this.initProfile} 
                                     scheme={this.state.scheme}/>;
            }
          } else if (this.state.selectAccount) {
            body = <SelectAccount config={this.state.config} userList={this.state.userList} currentUser={this.state.currentUser}/>;
          } else {
            body = <Body config={this.state.config} 
                         currentUser={this.state.currentUser} 
                         client={this.state.client} 
                         scope={this.state.scope} 
                         scheme={this.state.scheme} 
                         schemeListRequired={this.state.schemeListRequired} 
                         showGrant={this.state.showGrant} 
                         infoSomeScopeUnavailable={this.state.infoSomeScopeUnavailable}
                         validLogin={(!!this.state.config.params.callback_url && !!this.state.config.params.scope)}
                         authDetails={this.state.authDetails}/>;
            if (this.state.errorScopesUnavailable) {
              scopeUnavailable = <div className="alert alert-danger" role="alert">{i18next.t("login.error-scope-unavailable")}</div>
            }
          }
        }
      }
      var langList = [];
      this.state.config.lang.forEach((lang, i) => {
        if (lang === i18next.language) {
          langList.push(<a className="dropdown-item active" href="#" key={i}>{lang}</a>);
        } else {
          langList.push(<a className="dropdown-item" href="#" onClick={(e) => this.changeLang(e, lang)} key={i}>{lang}</a>);
        }
      });
      return (
        <div aria-live="polite" aria-atomic="true" className="glwd-container">
          <div className="card center glwd-card" id="userCard" tabIndex="-1" role="dialog">
            <div className="card-header">
              <nav className="navbar navbar-expand-lg navbar-light">
                <a className="navbar-brand" href="#" data-toggle="collapse">
                  <img className="mr-3" src="img/logo-login.png" alt="logo"/>
                  {i18next.t("login.menu-title")}
                </a>
                <button className="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
                  <span className="navbar-toggler-icon"></span>
                </button>
                <div className="collapse navbar-collapse" id="navbarSupportedContent">
                  <div className="btn-group" role="group">
                    <button className="btn btn-secondary dropdown-toggle" type="button" id="dropdownLang" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                      <i className="fas fa-language"></i>
                    </button>
                    <div className="dropdown-menu" aria-labelledby="dropdownLang">
                      {langList}
                    </div>
                  </div>
                </div>
              </nav>
            </div>
            {message}
            <div className="card-body">
              {scopeUnavailable}
              {body}
            </div>
            <div className="card-footer">
              <Buttons config={this.state.config} 
                       currentUser={this.state.currentUser} 
                       userList={this.state.userList}
                       client={this.state.client}
                       showGrant={this.state.showGrant} 
                       showGrantAsterisk={this.state.showGrantAsterisk || this.state.showAuthDetailsAsterisk} 
                       newUser={this.state.newUser} 
                       newUserScheme={this.state.scheme} 
                       canContinue={this.state.canContinue && !this.state.errorScopesUnavailable} 
                       schemeListRequired={this.state.schemeListRequired}
                       selectAccount={this.state.selectAccount} 
                       registration={this.state.registration}
                       resetCredentials={this.state.resetCredentials}
                       resetCredentialsShow={this.state.resetCredentialsShow} />
            </div>
          </div>
          <Notification loggedIn={true}/>
          <Message title={this.state.messageModal.title} label={this.state.messageModal.label} message={this.state.messageModal.message} />
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
