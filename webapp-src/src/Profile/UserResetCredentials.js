import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';

class UserResetCredentials extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      config: props.config,
      profile: props.profile,
      status: props.status,
      password: "",
      passwordConfirm: "",
      invalidPassword: false,
      password_set: false,
      modifyPassword: true
    };
    
    this.updatePassword = this.updatePassword.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      profile: nextProps.profile,
      status: nextProps.status
    });
  }
  
  changePassword(e) {
    this.setState({password: e.target.value}, () => {
      this.checkPassword();
    });
  }
  
  changeConfirmPassword(e) {
    this.setState({passwordConfirm: e.target.value}, () => {
      this.checkPassword();
    });
  }
  
  checkPassword() {
    var invalidPassword = false;
    if (this.state.password !== "" || this.state.passwordConfirm !== "") {
      if (this.state.password !== this.state.passwordConfirm) {
        invalidPassword = i18next.t("profile.register-password-error-not-match");
      } else if (this.state.password.length < (this.state.config.PasswordMinLength||8)) {
        invalidPassword = i18next.t("profile.register-password-ph", {car: (this.state.config.PasswordMinLength||8)});
      }
    }
    this.setState({invalidPassword: invalidPassword});
  }
  
  navigateProfile(e) {
    e.preventDefault();
    apiManager.glewlwydRequest("/" + this.state.config.params.resetCredentials + "/reset-credentials/profile/complete", "POST")
    .then(() => {
      var schemeDefault = false;
      this.state.config.sessionSchemes.forEach((scheme) => {
        if (scheme.scheme_default) {
          scheme.scheme_default.forEach((page) => {
            if (page === "admin") {
              schemeDefault = scheme.scheme_name;
            }
          });
        }
      });
      document.location.href = this.state.config.LoginUrl + "?callback_url=" + encodeURIComponent([location.protocol, '//', location.host, location.pathname].join('')) + "&scope=" + encodeURIComponent(this.state.config.profile_scope) + (schemeDefault?("&scheme="+encodeURIComponent(schemeDefault)):"") + "&prompt=login";
    })
    .fail((err) => {
      console.log(err);
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
    });
  }
  
  savePassword(e) {
    e.preventDefault();
    
    if (!this.state.invalidPassword && this.state.password.length >= (this.state.config.PasswordMinLength||8)) {
      apiManager.glewlwydRequest("/" + this.state.config.params.resetCredentials + "/reset-credentials/profile/password", "POST", {password: this.state.password})
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.register-password-saved")});
      })
      .fail((err) => {
        if (err.status !== 400) {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
        }
      })
      .always(() => {
        this.setState({password: "", passwordConfirm: "", modifyPassword: false, password_set: true});
      });
    }
  }
  
  updatePassword() {
    this.setState({modifyPassword: true, password_set: false});
  }
  
  render() {
    var callbackButton
    if (this.state.config.params.callback_url) {
      callbackButton =
        <a className="btn btn-success" href={decodeURI(this.state.config.params.callback_url)}>
          {i18next.t("callback.button-login")}
        </a>
    } else if (this.state.profile.callback_url) {
      callbackButton =
        <a className="btn btn-success" href={decodeURI(this.state.profile.callback_url)}>
          {i18next.t("callback.button-login")}
        </a>
    } else {
      callbackButton =
        <a className="btn btn-success" href="#" onClick={(e) => this.navigateProfile(e)}>
          {i18next.t("callback.button-profile")}
        </a>
    }
    if (this.state.status === 1) {
      return (
        <div>
          <div className="row">
            <div className="col-md-12">
              <h4>{i18next.t("profile.reset-credentials-hello", {name: (this.state.profile.name || this.state.profile.username)})}</h4>
            </div>
          </div>
          <hr/>
          <label htmlFor="password-input">
            {i18next.t("profile.register-password-label")}
            <button type="button" 
                    disabled={!this.state.password_set}
                    className="btn btn-outline-secondary btn-sm btn-icon-right" 
                    onClick={this.updatePassword}>
              <i className="fas fa-edit"></i>
            </button>
          </label>
          <div className="input-group">
            <input type="password" 
                   className={"form-control"} 
                   id="password-input"
                   disabled={this.state.password_set}
                   placeholder={i18next.t("profile.register-password-ph", {car: this.state.config.PasswordMinLength||8})} 
                   onChange={(e) => this.changePassword(e)} 
                   value={this.state.password}/>
          </div>
          <label htmlFor="confirm-password-input">{i18next.t("profile.register-confirm-password-label")}</label>
          <div className="input-group mb-3">
            <input type="password" 
                   className={"form-control"} 
                   id="confirm-password-input"
                   disabled={this.state.password_set}
                   placeholder={i18next.t("profile.register-confirm-password-ph")} 
                   onChange={(e) => this.changeConfirmPassword(e)} 
                   value={this.state.passwordConfirm}/>
            <div className="input-group-append">
              <button className="btn btn-secondary btn-icon" 
                      type="button" 
                      onClick={(e) => this.savePassword(e)}
                      disabled={this.state.invalidPassword || (!this.state.modifyPassword && this.state.password_set)}
                      title={i18next.t("save")}>
                {i18next.t("save")}
              </button>
            </div>
          </div>
          <hr/>
          <h5>{i18next.t("profile.reset-credentials-complete-message")}</h5>
          {callbackButton}
        </div>
      );
    } else if (this.state.status === -1) {
      return (
        <div>
          <div className="row">
            <div className="col-md-12">
              <h4>{i18next.t("profile.reset-credentials-error")}</h4>
            </div>
          </div>
        </div>
      );
    } else {
      return ("");
    }
  }
}

export default UserResetCredentials;
