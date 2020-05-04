import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';

class DeviceAuth extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      config: props.config,
      userCode: "",
    };
    this.handleValidCode = this.handleValidCode.bind(this);
    this.handleChangeUserCode = this.handleChangeUserCode.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      userCode: ""
    });
  }
  
  handleChangeUserCode(e) {
    var input = e.target.value.replace(/[\W\s\._\-]+/g, '').toUpperCase();
    if (input.length > 8) {
      input = input.substring(0, 8);
    }
    if (input.length >= 4) {
      input = input.substring(0, 4)+'-'+input.substring(4);
    }

    this.setState({
      userCode: input
    });
  }
  
  handleValidCode() {
    document.location = this.state.config.params.callback_url+"?code="+this.state.userCode;
  }
  
  render() {
    var contentJsx, buttonJsx;
    if (this.state.config.params.prompt === "deviceComplete") {
      contentJsx = 
      <div className="row">
        <div className="col-md-12">
          <h4>{i18next.t("login.device-authorization-complete-message")}</h4>
        </div>
      </div>
    } else if (this.state.config.params.prompt === "deviceServerError") {
      contentJsx = 
      <div className="row">
        <div className="col-md-12">
          <h4>{i18next.t("login.device-authorization-server-error-message")}</h4>
        </div>
      </div>
    } else if (this.state.config.params.prompt === "deviceCodeError") {
      contentJsx = 
      <div>
        <div className="row">
          <div className="col-md-12">
            <h4>{i18next.t("login.device-authorization-message")}</h4>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="username">{i18next.t("login.device-auth-user-code")}</label>
              </div>
              <input type="text" maxLength="9" placeholder={i18next.t("login.device-auth-user-code-ph")} value={this.state.userCode} onChange={this.handleChangeUserCode} />
            </div>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            <h4>{i18next.t("login.device-authorization-code-error-message")}</h4>
          </div>
        </div>
      </div>
      buttonJsx =
      <button type="button" className="btn btn-primary btn-icon" onClick={this.handleValidCode} disabled={this.state.userCode.length < 9}>
        <i className="fas fa-sign-out-alt btn-icon"></i>{i18next.t("login.btn-ok")}
      </button>;
    } else {
      contentJsx = 
      <div className="row">
        <div className="col-md-12">
          <h4>{i18next.t("login.device-authorization-message")}</h4>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="username">{i18next.t("login.device-auth-user-code")}</label>
            </div>
            <input type="text" maxLength="9" placeholder={i18next.t("login.device-auth-user-code-ph")} value={this.state.userCode} onChange={this.handleChangeUserCode} />
          </div>
        </div>
      </div>;
      buttonJsx =
      <button type="button" className="btn btn-primary btn-icon" onClick={this.handleValidCode} disabled={this.state.userCode.length < 9}>
        <i className="fas fa-sign-out-alt btn-icon"></i>{i18next.t("login.btn-ok")}
      </button>;
    }
    return (
    <div>
      <div className="row">
        <div className="col-md-12">
          <h3>{i18next.t("login.device-authorization-title")}</h3>
        </div>
      </div>
      <hr/>
      {contentJsx}
      <div className="row">
        <div className="col-md-12">
          {buttonJsx}
        </div>
      </div>
    </div>);
  }
}

export default DeviceAuth;
