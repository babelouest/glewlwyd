import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';

class PasswordForm extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      username: props.username,
      password: "",
      config: props.config,
      currentUser: props.currentUser,
      userList: props.userList
    };

    this.handleChangeUsername = this.handleChangeUsername.bind(this);
    this.handleChangePassword = this.handleChangePassword.bind(this);
    this.validateLogin = this.validateLogin.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      username: nextProps.username,
      password: "",
      config: nextProps.config,
      currentUser: nextProps.currentUser,
      userList: nextProps.userList
    });
  }
  
  handleChangeUsername(e) {
    this.setState({username: e.target.value});
  }

  handleChangePassword(e) {
    this.setState({password: e.target.value});
  }

  validateLogin(e) {
    e.preventDefault();
    if (this.state.username && this.state.password) {
      var scheme = {
        username: this.state.username,
        password: this.state.password
      };

      apiManager.glewlwydRequest("/auth/", "POST", scheme)
      .then(() => {
        messageDispatcher.sendMessage('App', {type: 'loginSuccess'});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-login")});
      });
    }
  }

  gotoManageUsers() {
    messageDispatcher.sendMessage('App', {type: 'SelectAccount'});
  }

	render() {
    var inputUsername, manageUsersButton;
    if (this.state.currentUser) {
      inputUsername = <input type="text" className="form-control" name="username" id="username" disabled={true} value={this.state.currentUser.username} />
    } else {
      inputUsername = <input type="text" className="form-control" name="username" id="username" required="" placeholder={i18next.t("login.login-placeholder")} value={this.state.username} onChange={this.handleChangeUsername} autoFocus={true}/>;
    }
    if (this.state.userList.length > 0) {
      manageUsersButton = <button type="button" className="btn btn-secondary" onClick={this.gotoManageUsers}>{i18next.t("login.manage-users")}</button>
    }
		return (
      <form action="#" id="passwordForm">
        <div className="form-group">
          <h4>{i18next.t("login.enter-login-password")}</h4>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="username">{i18next.t("login.login")}</label>
            </div>
            {inputUsername}
          </div>
        </div>
        <div className="form-group">
          <div className="input-group mb-3">
            <div className="input-group-prepend">
              <label className="input-group-text" htmlFor="password">{i18next.t("login.password")}</label>
            </div>
            <input type="password" className="form-control" name="password" id="password" required="" placeholder={i18next.t("login.password-placeholder")} value={this.state.password} onChange={this.handleChangePassword} autoFocus={!!this.state.currentUser}/>
          </div>
        </div>
        <div className="row">
          <div className="col-md-3">
              <button type="submit" name="loginbut" id="loginbut" className="btn btn-primary btn-lg btn-block" onClick={(e) => this.validateLogin(e)} title={i18next.t("login.sign-in-title")}>{i18next.t("login.btn-ok")}</button>
          </div>
          <div className="col-md-9 text-right mt-2">
            {manageUsersButton}
          </div>
        </div>
      </form>
		);
	}
}

export default PasswordForm;
