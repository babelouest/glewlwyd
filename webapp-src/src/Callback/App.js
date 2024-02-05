import React, { Component } from 'react';
import i18next from 'i18next';

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
              if (stateDecoded.complete_url.startsWith(config.GlewlwydUrl)) {
                var url = stateDecoded.complete_url;
                if (url.indexOf('?') > -1) {
                  url += '&';
                } else {
                  url += '?';
                }
                url += "scheme_name=" + encodeURIComponent(stateDecoded.module) + "&provider=" + encodeURIComponent(stateDecoded.provider);
                window.location.href = url;
              } else {
                this.setState({stateDecoded: stateDecoded, errorAuthentication: true, gotoProfile: true});
              }
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
            value: {
              provider: stateDecoded.provider,
              state: state,
              redirect_to: window.location.href
            }
          }
          if (stateDecoded.username) {
            data.username = stateDecoded.username;
          } else {
            data.value.action = "verify";
          }
          $.ajax({
            method: "POST",
            url: config.GlewlwydUrl + "/" + config.api_prefix + "/auth/",
            data: JSON.stringify(data),
            contentType: "application/json; charset=utf-8"
          })
          .then(() => {
            this.setState({stateDecoded: stateDecoded}, () => {
              if (stateDecoded.callback_url.startsWith(config.GlewlwydUrl)) {
                window.location.href = stateDecoded.callback_url;
              } else {
                this.setState({stateDecoded: false, unknownError: true, gotoLogin: true});
              }
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
    if (this.state.stateDecoded && this.state.stateDecoded.callback_url.startsWith(this.state.config.GlewlwydUrl)) {
      window.location.href = this.state.stateDecoded.callback_url;
    } else {
      this.setState({stateDecoded: false, unknownError: true, gotoLogin: true});
    }
  }
  
  gotoProfile() {
    if (this.state.stateDecoded && this.state.stateDecoded.complete_url) {
      if (this.state.stateDecoded.complete_url.startsWith(this.state.config.GlewlwydUrl)) {
        var url = this.state.stateDecoded.complete_url;
        if (url.indexOf('?') > -1) {
          url += '&';
        } else {
          url += '?';
        }
        url += "scheme_name=" + encodeURIComponent(this.state.stateDecoded.module) + "&provider=" + encodeURIComponent(this.state.stateDecoded.provider);
        window.location.href = url;
      } else {
        this.setState({stateDecoded: false, unknownError: true, gotoLogin: true});
      }
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
