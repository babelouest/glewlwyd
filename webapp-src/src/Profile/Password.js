import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

class Password extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      config: props.config,
      passwordMinLength: props.config.PasswordMinLength||8,
      callback: props.callback,
      loggedIn: props.loggedIn,
      registerPlugin: props.registerPlugin,
      old_password: "",
      password: "",
      password_confirm: "",
      oldPasswordInvalid: false,
      passwordInvalid: false,
      passwordConfirmInvalid: false
    }
    
    this.passwordButtonHandler = this.passwordButtonHandler.bind(this);
    this.changeOldPassword = this.changeOldPassword.bind(this);
    this.changeNewPassword = this.changeNewPassword.bind(this);
    this.changeNewPasswordConfirm = this.changeNewPasswordConfirm.bind(this);
    this.checkPassword = this.checkPassword.bind(this);
    this.resetCredentialsCodeReset = this.resetCredentialsCodeReset.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      passwordMinLength: nextProps.config.PasswordMinLength||8,
      callback: nextProps.callback,
      loggedIn: nextProps.loggedIn,
      registerPlugin: nextProps.registerPlugin
    }, () => {
      if (!this.state.loggedIn) {
        this.setState({
          password: '',
          old_password: '',
          password_confirm: '',
          passwordMinLength: 0
        });
      };
    });
  }
  
  passwordButtonHandler(e, result) {
    var apiError = false;

    if (result) {
      // Check whether the new password is well-formed.
      if (this.checkPassword()) {
        apiManager.glewlwydRequest("/profile/password", "PUT", {old_password: this.state.old_password, password: this.state.password})
        .then(() => {
          this.setState({old_password: "", 
                         password: "", 
                         password_confirm: "", 
                         oldPasswordInvalid: false, 
                         oldPasswordInvalidMessage: "",
                         passwordInvalid: false, 
                         passwordInvalidMessage: "", 
                         passwordConfirmInvalid: false,
                         passwordConfirmInvalidMessage: ""}, () => {
            this.state.callback(result);
          });
        })
        .fail((err) => {
           if (err.status == 400) {
             this.setState({oldPasswordInvalid: true, oldPasswordInvalidMessage: i18next.t("profile.password-invalid")});
           } else {
            apiError = true;
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
           }
        });
      }
    } else {
      this.state.callback(result);
    }
  }

  changeOldPassword(e) {
    this.setState({old_password: e.target.value});
  }
  
  changeNewPassword(e) {
    this.setState({password: e.target.value});
  }
  
  changeNewPasswordConfirm(e) {
    this.setState({password_confirm: e.target.value});
  }
  
  checkPassword() {
    var passwordInvalid = false, passwordConfirmInvalid = false, passwordInvalidMessage = "", passwordConfirmInvalidMessage = ""; 
    if (this.state.password.length < this.state.passwordMinLength) {
      passwordInvalid = true;
      passwordInvalidMessage = i18next.t("profile.password-min-characters", {minLength: this.state.passwordMinLength});
    }
    if (this.state.password !== this.state.password_confirm) {
      passwordConfirmInvalid = true;
      passwordConfirmInvalidMessage = i18next.t("profile.password-not-match");
    }
    this.setState({passwordInvalid: passwordInvalid, 
                   passwordConfirmInvalid: passwordConfirmInvalid, 
                   passwordInvalidMessage: passwordInvalidMessage, 
                   passwordConfirmInvalidMessage:passwordConfirmInvalidMessage});
    return !passwordInvalid && !passwordConfirmInvalid;
  }
  
  resetCredentialsCodeReset(plugin) {
    apiManager.glewlwydRequest("/" + plugin + "/reset-credentials-code", "PUT")
    .then((codes) => {
      messageDispatcher.sendMessage('App', {type: "message", title: i18next.t("profile.reset-credentials-code-reset-title"), label: i18next.t("profile.reset-credentials-code-reset-label-modal"), message: codes});
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
    });
  }
  
  render() {
    var resetCredentialsCodeJsx = [];
    this.state.registerPlugin.forEach((plugin, index) => {
      if (plugin["reset-credentials"].code) {
        resetCredentialsCodeJsx.push(
          <div className="card" key={index}>
            <div className="card-header" id={"headingResetCredCode"+plugin.name}>
              <h2 className="mb-0">
                <button className="btn btn-link btn-block text-left collapsed" type="button" data-toggle="collapse" data-target={"#collapseResetCredCode"+plugin.name} aria-expanded="false" aria-controls={"collapseResetCredCode"+plugin.name}>
                  {i18next.t("profile.reset-credentials-code-reset-title")}
                </button>
              </h2>
            </div>
            <div id={"collapseResetCredCode"+plugin.name} className="collapse" aria-labelledby={"headingResetCredCode"+plugin.name} data-parent="#accordionResetCredCode">
              <div className="card-body">
                <p>{i18next.t("profile.reset-credentials-code-reset-label")}</p>
                <button type="button" className="btn btn-primary" onClick={() => this.resetCredentialsCodeReset(plugin.name)}>
                  {i18next.t("profile.reset-credentials-code-reset-button")}
                </button>
              </div>
            </div>
          </div>
        );
      }
    });
    return (
      <div>
        <div className="row" id="password">
          <div className="col-md-12">
            <h4>{i18next.t("profile.password-title")}</h4>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            <form className="needs-validation" noValidate>
              <div className="form-group">
                <div className="input-group mb-3">
                  <div className="input-group-prepend">
                    <label className="input-group-text" htmlFor="mod-old-password">{i18next.t("profile.password-old-password")}</label>
                  </div>
                  <input type="password" 
                          autoComplete="current-password" 
                          className={"form-control" + (this.state.oldPasswordInvalid?" is-invalid":"")} 
                          id="oldPassword" 
                          placeholder={i18next.t("profile.password-old-password-ph")} 
                          value={this.state.old_password} 
                          onChange={(e) => this.changeOldPassword(e)} />
                </div>
                <span className={"error-input" + (this.state.oldPasswordInvalid?"":" hidden")}>{this.state.oldPasswordInvalidMessage}</span>
              </div>
              <div className="form-group">
                <div className="input-group mb-3">
                  <div className="input-group-prepend">
                    <label className="input-group-text" htmlFor="mod-new-password">{i18next.t("profile.password-new-password")}</label>
                  </div>
                  <input type="password" 
                          autoComplete="new-password" 
                          className={"form-control" + (this.state.passwordInvalid?" is-invalid":"")} 
                          id="newPassword" 
                          placeholder={i18next.t("profile.password-new-password-ph", {minLength: this.state.passwordMinLength})} 
                          value={this.state.password} 
                          onChange={(e) => this.changeNewPassword(e)} />
                </div>
                <span className={"error-input" + (this.state.passwordInvalid?"":" hidden")}>{this.state.passwordInvalidMessage}</span>
              </div>
              <div className="form-group">
                <div className="input-group mb-3">
                  <div className="input-group-prepend">
                    <label className="input-group-text" htmlFor="mod-new-password-confirm">{i18next.t("profile.password-new-password-confirm")}</label>
                  </div>
                  <input type="password" 
                          autoComplete="new-password" 
                          className={"form-control" + (this.state.passwordConfirmInvalid?" is-invalid":"")} 
                          id="retypeNewPassword" 
                          placeholder={i18next.t("profile.password-new-password-confirm-ph", {minLength: this.state.passwordMinLength})} 
                          value={this.state.password_confirm} 
                          onChange={(e) => this.changeNewPasswordConfirm(e)} />
                </div>
                <span className={"error-input" + (this.state.passwordConfirmInvalid?"":" hidden")}>{this.state.passwordConfirmInvalidMessage}</span>
              </div>
            </form>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12 text-right">
              <button type="button" className="btn btn-primary" onClick={(e) => this.passwordButtonHandler(e, true)}>{i18next.t("profile.save")}</button>
          </div>
        </div>
        <hr/>
        <div className="accordion" id="accordionResetCredCode">
          {resetCredentialsCodeJsx}
        </div>
      </div>
    );
  }
}

export default Password;
