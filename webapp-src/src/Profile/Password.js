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
      profile: props.profile,
      passwordMinLength: props.config.PasswordMinLength||8,
      callback: props.callback,
      loggedIn: props.loggedIn,
      registerPlugin: props.registerPlugin,
      old_password: "",
      password: this.initPassword(props.profile),
      password_confirm: this.initPassword(props.profile),
      pwdStatus: this.initPwdStatus(props.profile),
      oldPasswordInvalid: false,
      passwordInvalid: false,
      passwordInvalidMessage: false,
      passwordConfirmInvalid: false,
      passwordConfirmInvalidMessage: false,
      saveDisabled: Number.isInteger(props.profile.password)
    }

    this.initPassword = this.initPassword.bind(this);
    this.passwordButtonHandler = this.passwordButtonHandler.bind(this);
    this.changeOldPassword = this.changeOldPassword.bind(this);
    this.changeNewPassword = this.changeNewPassword.bind(this);
    this.changeNewPasswordConfirm = this.changeNewPasswordConfirm.bind(this);
    this.checkPassword = this.checkPassword.bind(this);
    this.resetCredentialsCodeReset = this.resetCredentialsCodeReset.bind(this);
    this.deletePasswordAt = this.deletePasswordAt.bind(this);
    this.addPassword = this.addPassword.bind(this);
    this.initPwdStatus = this.initPwdStatus.bind(this);
    this.setPwdStatus = this.setPwdStatus.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      profile: nextProps.profile,
      passwordMinLength: nextProps.config.PasswordMinLength||8,
      password: this.initPassword(nextProps.profile),
      password_confirm: this.initPassword(nextProps.profile),
      pwdStatus: this.initPwdStatus(nextProps.profile),
      callback: nextProps.callback,
      loggedIn: nextProps.loggedIn,
      registerPlugin: nextProps.registerPlugin,
      saveDisabled: Number.isInteger(nextProps.profile.password)
    }, () => {
      if (!this.state.loggedIn) {
        this.setState({
          password: "",
          old_password: "",
          password_confirm: "",
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
                         password: this.initPassword(this.state.profile),
                         password_confirm: this.initPassword(this.state.profile),
                         oldPasswordInvalid: false,
                         oldPasswordInvalidMessage: "",
                         passwordInvalid: false,
                         passwordInvalidMessage: "",
                         passwordConfirmInvalid: false,
                         passwordConfirmInvalidMessage: "",
                         pwdStatus: this.initPwdStatus(this.state.profile)}, () => {
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

  changeNewPassword(e, index = -1) {
    if (index > -1) {
      var password = this.state.password;
      password[index] = e.target.value;
      this.setState({password: password});
    } else {
      this.setState({password: e.target.value});
    }
  }

  changeNewPasswordConfirm(e, index = -1) {
    if (index > -1) {
      var password_confirm = this.state.password_confirm;
      password_confirm[index] = e.target.value;
      this.setState({password_confirm: password_confirm});
    } else {
      this.setState({password_confirm: e.target.value});
    }
  }

  checkPassword() {
    if (Array.isArray(this.state.password)) {
      var passwordInvalid = [], passwordConfirmInvalid = [], passwordInvalidMessage = [], passwordConfirmInvalidMessage = [], hasInvalid = false;
      for (var i=0; i<this.state.password.length; i++) {
        passwordInvalid.push(false);
        passwordConfirmInvalid.push(false);
        passwordInvalidMessage.push("");
        passwordConfirmInvalidMessage.push("");
        var password = this.state.password[i];
        var password_confirm = this.state.password_confirm[i];
        if (this.state.pwdStatus[i] === "set") {
          if (password !== null) {
            if (password.length < this.state.passwordMinLength) {
              passwordInvalid[i] = true;
              passwordInvalidMessage[i] = i18next.t("profile.password-min-characters", {minLength: this.state.passwordMinLength});
              hasInvalid = true;
            }
            if (password !== password_confirm) {
              passwordConfirmInvalid[i] = true;
              passwordConfirmInvalidMessage[i] = i18next.t("profile.password-not-match");
              hasInvalid = true;
            }
          }
        }
      }
      this.setState({passwordInvalid: passwordInvalid,
                     passwordConfirmInvalid: passwordConfirmInvalid,
                     passwordInvalidMessage: passwordInvalidMessage,
                     passwordConfirmInvalidMessage:passwordConfirmInvalidMessage});
      return !hasInvalid;
    } else {
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

  initPassword(profile) {
    if (Number.isInteger(profile.password)) {
      var password = [];
      for (var i=0; i<profile.password; i++) {
        password.push("");
      }
      return password;
    } else {
      return "";
    }
  }

  deletePasswordAt(index) {
    var password = this.state.password;
    var password_confirm = this.state.password_confirm;
    password[index] = null;
    password_confirm[index] = null;
    this.setState({password: password, password_confirm: password_confirm});
  }

  addPassword() {
    var password = this.state.password;
    var password_confirm = this.state.password_confirm;
    var pwdStatus = this.state.pwdStatus;
    password.push("");
    password_confirm.push("");
    pwdStatus.push("set");
    this.setState({password: password, password_confirm: password_confirm, pwdStatus: pwdStatus});
  }

  initPwdStatus(profile) {
    if (Number.isInteger(profile.password)) {
      var pwdStatus = [];
      for (var i=0; i<profile.password; i++) {
        pwdStatus.push("keep");
      }
      return pwdStatus;
    } else {
      return "";
    }
  }
  
  setPwdStatus(e, status, index) {
    e.preventDefault();
    var pwdStatus = this.state.pwdStatus;
    var saveDisabled = true;
    pwdStatus[index] = status;
    pwdStatus.forEach(status => {
      if (status === "set") {
        saveDisabled = false;
      }
    });
    this.setState({pwdStatus: pwdStatus, saveDisabled: saveDisabled});
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
    var passwordChangeJsx;
    if (Array.isArray(this.state.password)) {
      var passwordChangeList = [], counter = 0;
      this.state.password.forEach((password, index) => {
        if (password !== null) {
          counter++;
          passwordChangeList.push(
            <div key={index}>
              <div className="form-group">
                <div className="btn-group" role="group">
                  <div className="btn-group" role="group">
                    <div className="dropdown">
                      <button className="btn btn-secondary dropdown-toggle" type="button" id="modal-pwd" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                        <span className="badge badge-light btn-icon">
                          {counter}
                        </span>
                        {i18next.t("modal.pwd-" + (this.state.pwdStatus[index]))}
                      </button>
                      <div className="dropdown-menu" aria-labelledby="modal-pwd">
                        <a className="dropdown-item" href="#" onClick={(e) => this.setPwdStatus(e, "set", index)}>{i18next.t("modal.pwd-set")}</a>
                        <a className="dropdown-item" href="#" onClick={(e) => this.setPwdStatus(e, "keep", index)}>{i18next.t("modal.pwd-keep")}</a>
                      </div>
                    </div>
                    <button className="btn btn-secondary" type="button" onClick={(e) => this.deletePasswordAt(index)} title={i18next.t("admin.delete")}>
                      <i className="fas fa-trash"></i>
                    </button>
                  </div>
                </div>
                <div className="input-group mb-3">
                  <div className="input-group-prepend">
                    <label className="input-group-text" htmlFor="mod-new-password">{i18next.t("profile.password-new-password")}</label>
                  </div>
                  <input type="password"
                          autoComplete="new-password"
                          className={"form-control" + (this.state.passwordInvalid[index]?" is-invalid":"")}
                          id="newPassword"
                          placeholder={i18next.t("profile.password-new-password-ph", {minLength: this.state.passwordMinLength})}
                          value={password||""}
                          disabled={this.state.pwdStatus[index]==="keep"}
                          onChange={(e) => this.changeNewPassword(e, index)} />
                </div>
                <span className={"error-input" + (this.state.passwordInvalid[index]?"":" hidden")}>{this.state.passwordInvalidMessage[index]}</span>
              </div>
              <div className="form-group">
                <div className="input-group mb-3">
                  <div className="input-group-prepend">
                    <label className="input-group-text" htmlFor="mod-new-password-confirm">{i18next.t("profile.password-new-password-confirm")}</label>
                  </div>
                  <input type="password"
                          autoComplete="new-password"
                          className={"form-control" + (this.state.passwordConfirmInvalid[index]?" is-invalid":"")}
                          id="retypeNewPassword"
                          placeholder={i18next.t("profile.password-new-password-confirm-ph", {minLength: this.state.passwordMinLength})}
                          value={this.state.password_confirm[index]||""}
                          disabled={this.state.pwdStatus[index]==="keep"}
                          onChange={(e) => this.changeNewPasswordConfirm(e, index)} />
                </div>
                <span className={"error-input" + (this.state.passwordConfirmInvalid[index]?"":" hidden")}>{this.state.passwordConfirmInvalidMessage[index]}</span>
              </div>
            </div>
          );
        }
      });
      passwordChangeJsx =
        <div className="card">
          <div className="card-body">
            {passwordChangeList}
            <hr/>
            <button className="btn btn-secondary" type="button" onClick={this.addPassword} title={i18next.t("admin.add")}>
              <i className="fas fa-plus"></i>
            </button>
          </div>
        </div>
    } else {
      passwordChangeJsx =
        <div>
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
                      value={this.state.password||""}
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
                      value={this.state.password_confirm||""}
                      onChange={(e) => this.changeNewPasswordConfirm(e)} />
            </div>
            <span className={"error-input" + (this.state.passwordConfirmInvalid?"":" hidden")}>{this.state.passwordConfirmInvalidMessage}</span>
          </div>
        </div>;
    }
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
              {passwordChangeJsx}
            </form>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12 text-right">
              <button type="button" className="btn btn-primary" onClick={(e) => this.passwordButtonHandler(e, true)} disabled={this.state.saveDisabled}>{i18next.t("profile.save")}</button>
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
