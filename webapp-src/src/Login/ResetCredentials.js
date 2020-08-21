import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';

import messageDispatcher from '../lib/MessageDispatcher';

class ResetCredentials extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      config: props.config,
      resetCredentials: props.resetCredentials,
      username: {},
      code: {}
    };
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      resetCredentials: nextProps.resetCredentials
    });
  }
  
  sendEmail(e, resetCred) {
    e.preventDefault();
    apiManager.glewlwydRequest("/" + resetCred.name + "/reset-credentials-email", "POST", {username: this.state.username["email-"+resetCred.name]})
    .then(() => {
      messageDispatcher.sendMessage('App', {
        type: 'message',
        title: i18next.t("login.reset-credentials-title"), 
        label: i18next.t("login.reset-credentials-email-message-label")
      });
    })
    .fail((err) => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
    });
    return false;
  }
  
  sendCode(e, resetCred) {
    e.preventDefault();
    apiManager.glewlwydRequest("/" + resetCred.name + "/reset-credentials-code", "POST", {username: this.state.username["code-"+resetCred.name], code: this.state.code[resetCred.name]})
    .then(() => {
      window.location.href = this.state.config.ProfileUrl+"?resetCredentials="+resetCred.name;
    })
    .fail((err) => {
      if (err.status == 403) {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.reset-credentials-code-invalid")});
      } else {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      }
    });
    return false;
  }
  
  changeUsername(e, resetCred, email) {
    var username = this.state.username;
    username[(email?"email-":"code-")+resetCred] = e.target.value
    this.setState({username: username});
  }
  
  changeCode(e, resetCred) {
    var code = this.state.code;
    code[resetCred] = e.target.value
    this.setState({code: code});
  }
  
  render() {
    var emailBox = [], codeBox = [];
    this.state.resetCredentials.forEach((resetCred, index) => {
      if (resetCred.code) {
        if (codeBox.length) {
          codeBox.push(
            <div className="col-4 text-center" key={codeBox.length}>
              <h4>{i18next.t("admin.or")}</h4>
            </div>
          );
        }
        codeBox.push(
          <div className="col-4 card" key={codeBox.length}>
            <div className="card-body">
              <h5 className="card-title">{i18next.t("login.reset-credentials-code-title")}</h5>
              <form noValidate onSubmit={(e) => this.sendCode(e, resetCred)}>
                <div className="form-group">
                  <label htmlFor="username">{i18next.t("login.login")}</label>
                  <input type="text" className="form-control" name="username" id="username" value={this.state.username["code-"+resetCred.name]||""} onChange={(e) => this.changeUsername(e, resetCred.name, false)} />
                </div>
                <div className="form-group">
                  <label htmlFor="code">{i18next.t("login.reset-credentials-code-label")}</label>
                  <input type="text" className="form-control" name="code" id="code" value={this.state.code[resetCred.name]||""} onChange={(e) => this.changeCode(e, resetCred.name)} />
                </div>
                <button type="submit" className="btn btn-primary" disabled={!this.state.username["code-"+resetCred.name] || !this.state.code[resetCred.name]}>{i18next.t("login.reset-credentials-code-button")}</button>
              </form>
            </div>
          </div>
        );
      }
      if (resetCred.email) {
        if (codeBox.length || emailBox.length) {
          emailBox.push(
            <div className="col-4 text-center" key={codeBox.length+emailBox.length}>
              <h4>{i18next.t("admin.or")}</h4>
            </div>
          );
        }
        emailBox.push(
          <div className="col-4 card" key={codeBox.length+emailBox.length}>
            <div className="card-body">
              <h5 className="card-title">{i18next.t("login.reset-credentials-email-title")}</h5>
              <form noValidate onSubmit={(e) => this.sendEmail(e, resetCred)}>
                <div className="form-group">
                  <label htmlFor="username">{i18next.t("login.login")}</label>
                  <input type="text" className="form-control" name="username" id="username" value={this.state.username["email-"+resetCred.name]||""} onChange={(e) => this.changeUsername(e, resetCred.name, true)} />
                </div>
                <button type="submit" className="btn btn-primary" disabled={!this.state.username["email-"+resetCred.name]}>{i18next.t("login.reset-credentials-email-button")}</button>
              </form>
            </div>
          </div>
        );
      }
    });
    return (
      <div>
        <h3>{i18next.t("login.reset-credentials-title")}</h3>
        <hr/>
        <div className="d-flex justify-content-around">
          {codeBox}
          {emailBox}
        </div>
      </div>
    );
  }
}

export default ResetCredentials;
