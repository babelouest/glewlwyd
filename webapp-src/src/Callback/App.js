import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import Notification from '../lib/Notification';

class App extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      config: props.config,
      errorAuthentication: false,
      unknownError: this.parseState(props.config.params.state, props.config),
      gotoProfile: false,
      gotoLogin: false
    };
    
    this.gotoLogin = this.gotoLogin.bind(this);
    this.gotoProfile = this.gotoProfile.bind(this);
  }
  
  Base64DecodeUrl(str){
    if (str.length % 4 == 2) {
      str += '==';
    } else if (str.length % 4 == 3) {
      str += '=';
    }
    return str.replace(/-/g, '+').replace(/_/g, '/');
  }
  
  parseState(state, config) {
    var unknownError = false;
    if (state) {
      var stateDecoded = false, type = false, hasError = false;
      try {
        var stateDecoded = JSON.parse(atob(this.Base64DecodeUrl(state)));
      } catch(e) {
        hasError = true;
      }
      if (!hasError) {
        if (stateDecoded.type === "registration") {
          type = "registration";
          var data = {
            scheme_name: stateDecoded.module,
            scheme_type: "oauth2",
            username: stateDecoded.username,
            value: {
              action: "callback",
              provider: stateDecoded.provider,
              state: state,
              redirect_to: window.location.href
            }
          }
          $.ajax({
            method: "POST",
            url: stateDecoded.register_url + "/profile/scheme/register/",
            data: JSON.stringify(data),
            contentType: "application/json; charset=utf-8"
          })
          .then(() => {
            this.setState({stateDecoded: stateDecoded}, () => {
              var url = stateDecoded.complete_url;
              if (url.indexOf('?') > -1) {
                url += '&';
              } else {
                url += '?';
              }
              url += "scheme_name=" + stateDecoded.module + "&provider=" + stateDecoded.provider;
              window.location.href = url;
            });
          })
          .fail((err) => {
            if (err.status === 401) {
              this.setState({stateDecoded: stateDecoded, errorAuthentication: true, gotoProfile: true});
            } else {
              this.setState({stateDecoded: stateDecoded, unknownError: true, gotoProfile: true});
            }
          });
        } else if (stateDecoded.type === "authentication") {
          type = "authentication";
          var data = {
            scheme_name: stateDecoded.module,
            scheme_type: "oauth2",
            username: stateDecoded.username,
            value: {
              provider: stateDecoded.provider,
              state: state,
              redirect_to: window.location.href
            }
          }
          $.ajax({
            method: "POST",
            url: config.GlewlwydUrl + "/" + config.api_prefix + "/auth/",
            data: JSON.stringify(data),
            contentType: "application/json; charset=utf-8"
          })
          .then(() => {
            this.setState({stateDecoded: stateDecoded}, () => {
              window.location.href = stateDecoded.callback_url;
            });
          })
          .fail((err) => {
            if (err.status === 401) {
              this.setState({stateDecoded: stateDecoded, errorAuthentication: true, gotoLogin: true});
            } else {
              this.setState({stateDecoded: stateDecoded, unknownError: true, gotoLogin: true});
            }
          });
        } else {
          unknownError = true;
        }
      } else {
        unknownError = true;
      }
    } else {
      unknownError = true;
    }
    return unknownError;
  }
  
  gotoLogin() {
    window.location.href = this.state.stateDecoded.callback_url;
  }
  
  gotoProfile() {
    if (this.state.stateDecoded && this.state.stateDecoded.complete_url) {
      var url = this.state.stateDecoded.complete_url;
      if (url.indexOf('?') > -1) {
        url += '&';
      } else {
        url += '?';
      }
      url += "scheme_name=" + this.state.stateDecoded.module + "&provider=" + this.state.stateDecoded.provider;
      window.location.href = url;
    } else {
      window.location.href = this.state.config.ProfileUrl;
    }
  }

	render() {
    if (this.state.config) {
      if (this.state.errorAuthentication || this.state.unknownError) {
        var button;
        if (this.state.gotoLogin) {
          button = <button type="button" className="btn btn-primary" id="buttonBack" onClick={this.gotoLogin}>{i18next.t("callback.button-login")}</button>
        } else {
          button = <button type="button" className="btn btn-primary" id="buttonBack" onClick={this.gotoProfile}>{i18next.t("callback.button-profile")}</button>
        }
        return (
        <div className="perfect-centering">
          <div className="alert alert-danger">
            <h3>
              {(this.state.errorAuthentication?i18next.t("callback.authentication-error"):i18next.t("callback.unknown-error"))}
            </h3>
          </div>
          <div className="row justify-content-md-center">
            {button}
          </div>
        </div>
        );
      } else {
        return (
        <div className="perfect-centering">
          <div className="alert alert-info">
            <h3>
              {i18next.t("callback.authentication-success")}
            </h3>
          </div>
        </div>
        );
      }
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
