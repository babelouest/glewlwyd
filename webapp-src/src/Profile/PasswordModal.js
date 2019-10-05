import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

class PasswordModal extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      config: props.config,
      passwordMinLength: props.config.PasswordMinLength||8,
      callback: props.callback,
      old_password: "",
      password: "",
      password_confirm: "",
      oldPasswordInvalid: false,
      passwordInvalid: false,
      passwordConfirmInvalid: false
    }
    
    this.closeModal = this.closeModal.bind(this);
    this.changeOldPassword = this.changeOldPassword.bind(this);
    this.changeNewPassword = this.changeNewPassword.bind(this);
    this.changeNewPasswordConfirm = this.changeNewPasswordConfirm.bind(this);
    this.checkPassword = this.checkPassword.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      passwordMinLength: nextProps.config.PasswordMinLength||8,
      callback: nextProps.callback,
      old_password: "",
      password: "",
      password_confirm: "",
      oldPasswordInvalid: false,
      passwordInvalid: false,
      passwordConfirmInvalid: false
    });
  }
  
  closeModal(e, result) {
    if (result) {
      if (this.checkPassword()) {
        apiManager.glewlwydRequest("/profile/password", "PUT", {old_password: this.state.old_password, password: this.state.password})
        .then(() => {
          this.setState({oldPasswordInvalid: false}, () => {
            this.state.callback(result);
          });
        })
        .fail((err) => {
          if (err.status == 400) {
            this.setState({oldPasswordInvalid: true, oldPasswordInvalidMessage: i18next.t("profile.password-invalid")});
          } else {
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
    this.setState({passwordInvalid: passwordInvalid, passwordConfirmInvalid: passwordConfirmInvalid, passwordInvalidMessage: passwordInvalidMessage, passwordConfirmInvalidMessage:passwordConfirmInvalidMessage});
    return !passwordInvalid && !passwordConfirmInvalid;
  }
  
  render() {
    return (
      <div className="modal fade" id="passwordModal" tabIndex="-1" role="dialog" aria-labelledby="confirmModalLabel" aria-hidden="true">
        <div className="modal-dialog modal-lg" role="document">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title" id="confirmModalLabel">{i18next.t("profile.password-modal-title")}</h5>
              <button type="button" className="close" aria-label={i18next.t("modal.close")} onClick={(e) => this.closeModal(e, false)}>
                <span aria-hidden="true">&times;</span>
              </button>
            </div>
            <div className="modal-body">
              <form className="needs-validation" noValidate>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-old-password">{i18next.t("profile.password-modal-old-password")}</label>
                    </div>
                    <input type="password" 
                           autoComplete="current-password" 
                           className={"form-control" + (this.state.oldPasswordInvalid?" is-invalid":"")} 
                           id="mod-name" 
                           placeholder={i18next.t("profile.password-modal-old-password-ph")} 
                           value={this.state.old_password} 
                           onChange={(e) => this.changeOldPassword(e)} />
                  </div>
                  <span className={"error-input" + (this.state.oldPasswordInvalid?"":" hidden")}>{this.state.oldPasswordInvalidMessage}</span>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-new-password">{i18next.t("profile.password-modal-new-password")}</label>
                    </div>
                    <input type="password" 
                           autoComplete="new-password" 
                           className={"form-control" + (this.state.passwordInvalid?" is-invalid":"")} 
                           id="mod-name" 
                           placeholder={i18next.t("profile.password-modal-new-password-ph", {minLength: this.state.passwordMinLength})} 
                           value={this.state.password} 
                           onChange={(e) => this.changeNewPassword(e)} />
                  </div>
                  <span className={"error-input" + (this.state.passwordInvalid?"":" hidden")}>{this.state.passwordInvalidMessage}</span>
                </div>
                <div className="form-group">
                  <div className="input-group mb-3">
                    <div className="input-group-prepend">
                      <label className="input-group-text" htmlFor="mod-new-password-confirm">{i18next.t("profile.password-modal-new-password-confirm")}</label>
                    </div>
                    <input type="password" 
                           autoComplete="new-password" 
                           className={"form-control" + (this.state.passwordConfirmInvalid?" is-invalid":"")} 
                           id="mod-name" 
                           placeholder={i18next.t("profile.password-modal-new-password-confirm-ph", {minLength: this.state.passwordMinLength})} 
                           value={this.state.password_confirm} 
                           onChange={(e) => this.changeNewPasswordConfirm(e)} />
                  </div>
                  <span className={"error-input" + (this.state.passwordConfirmInvalid?"":" hidden")}>{this.state.passwordConfirmInvalidMessage}</span>
                </div>
              </form>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={(e) => this.closeModal(e, false)}>{i18next.t("modal.close")}</button>
              <button type="button" className="btn btn-primary" onClick={(e) => this.closeModal(e, true)}>{i18next.t("modal.ok")}</button>
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default PasswordModal;
