import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';

class Register extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      config: props.config,
      registerConfig: props.registerConfig,
      registerProfile: props.registerProfile,
      registerSchemes: props.registerSchemes,
      username: "",
      usernameValid: false,
      verificationSent: false,
      email: "",
      code: "",
      invalidCode: false,
      showCode: false,
      timeout: false,
      checkingUsername: false,
      invalidMessage: false,
      invalidEmailMessage: true,
      password: "",
      passwordConfirm: "",
      invalidPassword: false,
      registerComplete: false
    };
    
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      registerConfig: nextProps.registerConfig,
      registerProfile: nextProps.registerProfile
    });
  }
  
  checkUsername() {
    if (this.state.timeout) {
      clearTimeout(this.state.timeout);
    }
    if (this.state.username) {
      apiManager.glewlwydRequest("/" + this.state.config.params.register + "/username", "POST", {username: this.state.username})
      .then(() => {
        this.setState({timeout: false, usernameValid: true, checkingUsername: false, invalidMessage: false});
      })
      .fail((err) => {
        this.setState({timeout: false, usernameValid: false, checkingUsername: false, invalidMessage: true}, () => {
          if (err.status !== 400) {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
            this.setState({invalidMessage: true});
          }
        });
      });
    }
  }
  
  changeUsername(e) {
    e.preventDefault();
    this.setState({username: e.target.value}, () => {
      if (this.state.timeout) {
        clearTimeout(this.state.timeout);
      }
      this.setState({
        checkingUsername: true,
        timeout: setTimeout(() => {
          this.checkUsername();
        }, 1000)
      });
    });
  }
  
  changeEmailVerification(e) {
    var usernameValid = this.state.usernameValid;
    if (this.state.registerConfig["email-is-username"]) {
      usernameValid = true;
    }
    this.setState({email: e.target.value, invalidEmailMessage: !e.target.value, usernameValid: usernameValid});
  }
  
  changeCode(e) {
    this.setState({code: e.target.value, invalidCode: !e.target.value});
  }
  
  changeName(e) {
    e.preventDefault();
    var profile = this.state.registerProfile;
    profile.name = e.target.value;
    this.setState({registerProfile: profile});
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
  
  registerUsername() {
    apiManager.glewlwydRequest("/" + this.state.config.params.register + "/register", "POST", {username: this.state.username})
    .then(() => {
      messageDispatcher.sendMessage('App', {type: "registration"});
    })
    .fail(() => {
      if (err.status !== 400) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      }
    });
  }
  
  saveProfile(e) {
    e.preventDefault();
    
    apiManager.glewlwydRequest("/" + this.state.config.params.register + "/profile", "PUT", this.state.registerProfile)
    .then(() => {
      if (!this.state.invalidPassword && this.state.password.length >= (this.state.config.PasswordMinLength||8)) {
        apiManager.glewlwydRequest("/" + this.state.config.params.register + "/profile/password", "POST", {password: this.state.password})
        .then(() => {
          messageDispatcher.sendMessage('App', {type: "registration"});
          messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.register-profile-saved")});
        })
        .fail(() => {
          if (err.status !== 400) {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
          }
        });
      } else {
        messageDispatcher.sendMessage('App', {type: "registration"});
      }
    })
    .fail((err) => {
      if (err.status !== 400) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      }
    });
  }
  
  sendVerificationEmail() {
    apiManager.glewlwydRequest("/" + this.state.config.params.register + "/verify", "PUT", {username: this.state.username, email: this.state.email})
    .then(() => {
      this.setState({verificationSent: true});
    })
    .fail((err) => {
      if (err.status !== 400) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      }
    });
  }
  
  verifyCode() {
    apiManager.glewlwydRequest("/" + this.state.config.params.register + "/verify", "POST", {username: this.state.username, email: this.state.email, code: this.state.code})
    .then(() => {
      messageDispatcher.sendMessage('App', {type: "registration"});
      messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.register-profile-created")});
    })
    .fail((err) => {
      this.setState({invalidCode: true}, () => {
        if (err.status !== 400) {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
        }
      });
    });
  }
  
  completeRegistration() {
    apiManager.glewlwydRequest("/" + this.state.config.params.register + "/profile/complete", "POST")
    .then(() => {
      this.setState({registerComplete: true, username: ""}, () => {
        messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.register-profile-completed")});
        messageDispatcher.sendMessage('App', {type: "registrationComplete"});
      });
    })
    .fail((err) => {
      if (err.status !== 400) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      } else {
        messageDispatcher.sendMessage('Notification', {type: "warning", message: i18next.t("profile.register-profile-incomplete")});
      }
    });
  }
  
  cancelRegistration() {
    apiManager.glewlwydRequest("/" + this.state.config.params.register + "/profile", "DELETE")
    .then(() => {
      this.setState({username: "", usernameValid: false, email: "", verificationSent: false, code: ""}, () => {
        messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.register-profile-cancelled")});
        messageDispatcher.sendMessage('App', {type: "registration"});
      });
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
    });
  }
  
  render() {
    var formJsx, completeMessageJsx, buttonJsx, passwordJsx, emailJsx;
    if (this.state.registerComplete) {
      completeMessageJsx = 
      <div>
        <div className="alert alert-info" role="alert">
          {i18next.t("profile.register-profile-complete-message")}
        </div>
        <div>
          <a className="btn btn-primary" href={this.state.config.ProfileUrl}>{i18next.t("profile.register-profile-complete-link")}</a>
        </div>
      </div>
    } else if (this.state.registerProfile) {
      var completeSteps = [], completeMessage;
      if (this.state.registerConfig["set-password"] === "always" && !this.state.registerProfile.password_set) {
        completeSteps.push(
        <li key={0}>
          {i18next.t("profile.register-profile-complete-step-password")}
        </li>
        );
      }
      if (this.state.registerConfig.schemes) {
        this.state.registerConfig.schemes.forEach((scheme, index) => {
          if (scheme.register == "always" && !this.state.registerSchemes[scheme.name]) {
            completeSteps.push(
            <li key={index+1}>
              {i18next.t("profile.register-profile-complete-step-scheme", {scheme: scheme.display_name})}
            </li>
            );
          }
        });
      }
      if (completeSteps.length) {
        completeMessage = i18next.t("profile.register-profile-complete-steps");
      } else {
        completeMessage = i18next.t("profile.register-profile-complete-possible");
      }
      if (this.state.registerConfig["set-password"] !== "no") {
        passwordJsx =
        <div>
          <hr/>
          <label htmlFor="password-input">{i18next.t("profile.register-password-label")}</label>
          <div className="input-group">
            <input type="password" 
                   className={"form-control"} 
                   id="password-input"
                   placeholder={i18next.t("profile.register-password-ph", {car: this.state.config.PasswordMinLength||8})} 
                   onChange={(e) => this.changePassword(e)} 
                   value={this.state.password}/>
          </div>
          <label htmlFor="confirm-password-input">{i18next.t("profile.register-confirm-password-label")}</label>
          <div className="input-group">
            <input type="password" 
                   className={"form-control"} 
                   id="confirm-password-input"
                   placeholder={i18next.t("profile.register-confirm-password-ph")} 
                   onChange={(e) => this.changeConfirmPassword(e)} 
                   value={this.state.passwordConfirm}/>
          </div>
          {this.state.invalidPassword?<span className="error-input">{this.state.invalidPassword}</span>:""}
        </div>
      }
      if (this.state.registerConfig["verify-email"]) {
        emailJsx =
        <div>
          <hr/>
          <label htmlFor="email-input">{i18next.t("profile.register-email-label")}</label>
          <div className="input-group">
            <input type="text" 
                   className={"form-control"} 
                   id="email-input"
                   disabled={true}
                   value={this.state.registerProfile.email||""}/>
          </div>
        </div>
      }
      formJsx =
        <form className="needs-validation" noValidate onSubmit={(e) => this.saveProfile(e)}>
          <label htmlFor="username-input">{i18next.t("profile.register-profile-username-label")}</label>
          <div className="input-group">
            <input type="text" 
                   className={"form-control"} 
                   value={this.state.registerProfile.username}
                   disabled={true}/>
          </div>
          {emailJsx}
          <hr/>
          <label htmlFor="name-input">{i18next.t("profile.register-name-label")}</label>
          <div className="input-group">
            <input type="text" 
                   className={"form-control"} 
                   id="name-input"
                   placeholder={i18next.t("profile.register-name-ph")} 
                   onChange={(e) => this.changeName(e)} 
                   value={this.state.registerProfile.name||""}/>
          </div>
          {passwordJsx}
          <hr/>
          <div className="alert alert-info" role="alert">
            {completeMessage}
            <ul>
              {completeSteps}
            </ul>
          </div>
        </form>
        buttonJsx =
          <div>
            <button className="btn btn-secondary btn-icon" 
                    type="submit" 
                    onClick={(e) => this.saveProfile(e)}
                    disabled={this.state.invalidPassword}
                    title={i18next.t("save")}>
              {i18next.t("save")}
            </button>
            <button className="btn btn-primary btn-icon"
                    type="button" 
                    onClick={() => this.completeRegistration()} 
                    title={i18next.t("profile.register-profile-complete")}>
              {i18next.t("profile.register-profile-complete")}
            </button>
            <button className="btn btn-primary"
                    type="button" 
                    onClick={() => this.cancelRegistration()} 
                    title={i18next.t("profile.register-profile-cancel")}>
              {i18next.t("profile.register-profile-cancel")}
            </button>
          </div>
    } else if (!this.state.registerProfile) {
      if (this.state.registerConfig["verify-email"]) {
        var buttonVerifyJsx, codeInputJsx;
        if (this.state.verificationSent) {
          codeInputJsx =
            <div>
              <hr/>
              <label htmlFor="code-input">{i18next.t("profile.register-code-label")}</label>
              <div className="input-group">
                <input type="text" 
                       className={"form-control"} 
                       id="code-input"
                       placeholder={i18next.t("profile.register-code-ph")} 
                       onChange={(e) => this.changeCode(e)} 
                       value={this.state.code}/>
                {this.state.invalidCode?<span className="error-input">{i18next.t("profile.register-code-error")}</span>:""}
              </div>
            </div>
          buttonVerifyJsx = 
            <button className="btn btn-success" 
                    type="button" 
                    onClick={() => this.verifyCode()} 
                    title={i18next.t("profile.register-profile-verify-code")}>
              {i18next.t("profile.register-profile-verify-code")}
            </button>
        } else {
          buttonVerifyJsx = 
            <button className="btn btn-success" 
                    type="button" 
                    onClick={() => this.sendVerificationEmail()} 
                    disabled={!this.state.usernameValid || !this.state.email}
                    title={i18next.t("profile.register-profile-verify-email")}>
              {i18next.t("profile.register-profile-verify-email")}
            </button>
        }
        if (this.state.registerConfig["email-is-username"]) {
          formJsx = 
            <form className="needs-validation" noValidate>
              <label htmlFor="email-input">{i18next.t("profile.register-email-label")}</label>
              <div className="input-group">
                <input type="text" 
                       className={"form-control"} 
                       id="email-input"
                       placeholder={i18next.t("profile.register-email-ph")} 
                       onChange={(e) => this.changeEmailVerification(e)} 
                       disabled={this.state.verificationSent}
                       value={this.state.email}/>
                {this.state.invalidEmailMessage?<span className="error-input">{i18next.t("profile.register-email-error")}</span>:""}
              </div>
              {codeInputJsx}
              <hr/>
              <div className="input-group-append">
                {buttonVerifyJsx}
              </div>
            </form>
        } else {
          formJsx = 
            <form className="needs-validation" noValidate>
              <label htmlFor="username-input">{i18next.t("profile.register-username-label")}</label>
              <div className="input-group">
                <input type="text" 
                       className={"form-control"} 
                       id="username-input"
                       placeholder={i18next.t("profile.register-username-ph")} 
                       onChange={(e) => this.changeUsername(e)} 
                       disabled={this.state.verificationSent}
                       value={this.state.username}/>
                {this.state.invalidMessage?<span className="error-input">{i18next.t("profile.register-username-error")}</span>:""}
              </div>
              <hr/>
              <label htmlFor="email-input">{i18next.t("profile.register-email-label")}</label>
              <div className="input-group">
                <input type="text" 
                       className={"form-control"} 
                       id="email-input"
                       placeholder={i18next.t("profile.register-email-ph")} 
                       onChange={(e) => this.changeEmailVerification(e)} 
                       disabled={this.state.verificationSent}
                       value={this.state.email}/>
                {this.state.invalidEmailMessage?<span className="error-input">{i18next.t("profile.register-email-error")}</span>:""}
              </div>
              {codeInputJsx}
              <hr/>
              <div className="input-group-append">
                {buttonVerifyJsx}
              </div>
            </form>
        }
      } else {
        formJsx = 
          <form className="needs-validation" noValidate>
            <label htmlFor="username-input">{i18next.t("profile.register-username-label")}</label>
            <div className="input-group">
              <input type="text" 
                     className={"form-control"} 
                     id="username-input"
                     placeholder={i18next.t("profile.register-username-ph")} 
                     onChange={(e) => this.changeUsername(e)} 
                     value={this.state.username}/>
              <div className="input-group-append">
                <button className={"btn" + ((this.state.usernameValid&&!this.state.checkingUsername)?" btn-outline-success":" btn-outline-danger")} 
                        type="button" 
                        onClick={() => this.registerUsername()} 
                        disabled={!this.state.usernameValid}
                        title={i18next.t("profile.register-username-create")}>
                  <i className={(this.state.checkingUsername?"fas fa-compass fa-spin":"fas fa-plus")}></i>
                </button>
              </div>
              {this.state.invalidMessage?<span className="error-input">{i18next.t("profile.register-username-error")}</span>:""}
            </div>
          </form>
      }
    }
    return (
      <div>
        <div className="row">
          <div className="col-md-12">
            <h4>{i18next.t("profile.register-title")}</h4>
          </div>
        </div>
        {completeMessageJsx}
        <div className="row">
          <div className="col-md-6">
            {formJsx}
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            {buttonJsx}
          </div>
        </div>
      </div>
    );
  }
}

export default Register;
