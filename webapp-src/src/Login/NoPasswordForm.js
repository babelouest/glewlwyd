import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';

import MockSchemeForm from './scheme/MockSchemeForm';
import EmailSchemeForm from './scheme/EmailSchemeForm';
import WebauthnForm from './scheme/WebauthnForm';
import OTPSchemeForm from './scheme/OTPSchemeForm';
import PasswordSchemeForm from './scheme/PasswordSchemeForm';
import CertificateSchemeForm from './scheme/CertificateSchemeForm';
import Oauth2SchemeForm from './scheme/Oauth2SchemeForm';

class NoPasswordForm extends Component {
  constructor(props) {
    super(props);
    this.state = {
      config: props.config,
      username: props.username,
      usernameValidated: false,
      scheme: props.scheme,
      userList: props.userList
    };

    this.handleChangeUsername = this.handleChangeUsername.bind(this);
    this.validateUsername = this.validateUsername.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      username: nextProps.username,
      scheme: nextProps.scheme,
      userList: nextProps.userList
    });
  }

  handleChangeUsername(e) {
    this.setState({username: e.target.value});
  }
  
  validateUsername(e) {
    e.preventDefault();
    if (this.state.username) {
      this.setState({usernameValidated: true});
    }
  }

  gotoManageUsers(e) {
    e.preventDefault();
    document.location.href = this.state.config.LoginUrl + "?callback_url=" + encodeURIComponent([location.protocol, '//', location.host, location.pathname].join('')) + "&scope=" + encodeURIComponent(this.state.config.profile_scope) + "&prompt=select_account";  
  }

	render() {
    var manageUsersButton;
    if (this.state.userList.length > 0) {
      manageUsersButton = <button type="button" className="btn btn-secondary" onClick={(e) => this.gotoManageUsers(e)}>{i18next.t("login.manage-users")}</button>
    }
    if (!this.state.usernameValidated) {
      return (
        <form action="#" id="passwordForm">
          <div className="form-group">
            <h4>{i18next.t("login.enter-login")}</h4>
          </div>
          <div className="form-group">
            <div className="input-group mb-3">
              <div className="input-group-prepend">
                <label className="input-group-text" htmlFor="username">{i18next.t("login.login")}</label>
              </div>
              <input type="text" className="form-control" name="username" id="username" autoFocus={true} required="" placeholder={i18next.t("login.login-placeholder")} value={this.state.username} onChange={this.handleChangeUsername} autoFocus/>
            </div>
          </div>
          <div className="row">
            <div className="col-md-3">
              <button type="submit" name="usernamebut" id="usernamebut" className="btn btn-primary btn-lg btn-block" onClick={(e) => this.validateUsername(e)} title={i18next.t("login.sign-in-title")}>{i18next.t("login.btn-ok")}</button>
            </div>
            <div className="col-md-9 text-right mt-2">
              {manageUsersButton}
            </div>
          </div>
        </form>
      );
    } else {
      var curScheme = false;
      this.state.config.sessionSchemes.forEach((scheme) => {
        if (scheme.scheme_name === this.state.scheme) {
          if (scheme.scheme_type === "mock") {
            curScheme = <MockSchemeForm config={this.state.config} scheme={scheme} currentUser={{username: this.state.username}}/>;
          } else if (scheme.scheme_type === "email") {
            curScheme = <EmailSchemeForm config={this.state.config} scheme={scheme} currentUser={{username: this.state.username}}/>;
          } else if (scheme.scheme_type === "webauthn") {
            curScheme = <WebauthnForm config={this.state.config} scheme={scheme} currentUser={{username: this.state.username}}/>;
          } else if (scheme.scheme_type === "otp") {
            curScheme = <OTPSchemeForm config={this.state.config} scheme={scheme} currentUser={{username: this.state.username}}/>;
          } else if (scheme.scheme_type === "retype-password" || scheme.scheme_type === "http") {
            curScheme = <PasswordSchemeForm config={this.state.config} scheme={scheme} currentUser={{username: this.state.username}}/>;
          } else if (scheme.scheme_type === "certificate") {
            curScheme = <CertificateSchemeForm config={this.state.config} scheme={scheme} currentUser={{username: this.state.username}}/>;
          } else if (scheme.scheme_type === "oauth2") {
            curScheme = <Oauth2SchemeForm config={this.state.config} scheme={scheme} currentUser={{username: this.state.username}}/>;
          } else {
            curScheme = <div>No can do</div>;
          }
        }
      });
      return (
        <div>
          <div className="form-group">
            <h4>{i18next.t("login.welcome-login", {username: this.state.username})}</h4>
          </div>
          <div className="form-group">
            {curScheme}
          </div>
          <div className="form-group">
            <div className="row">
              <div className="col-md-12 text-right mt-2">
                {manageUsersButton}
              </div>
            </div>
          </div>
        </div>
      );
    }
	}
}

export default NoPasswordForm;
