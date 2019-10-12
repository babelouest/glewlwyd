import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';

class SelectAccount extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      config: props.config,
      userList: props.userList||[],
      currentUser: props.currentUser||[]
    };
    
    this.handleSelectAccount = this.handleSelectAccount.bind(this);
    this.handleToggleGrantScope = this.handleToggleGrantScope.bind(this);
    this.handleNewAccount = this.handleNewAccount.bind(this);
    this.handleLogoutAccount = this.handleLogoutAccount.bind(this);
  }
  
  UNSAFE_componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      userList: nextProps.userList||[],
      currentUser: nextProps.currentUser||[]
    });
  }
  
  handleSelectAccount() {
    apiManager.glewlwydRequest("/auth/", "POST", {username: this.state.currentUser.username})
    .then(() => {
      messageDispatcher.sendMessage('App', {type: 'SelectAccountComplete'});
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-login")});
    });
  }
  
  handleToggleGrantScope(user) {
    this.setState({currentUser: user});
  }
  
  handleNewAccount() {
    messageDispatcher.sendMessage('App', {type: 'NewUser'});
  }
  
  handleLogoutAccount(username) {
    apiManager.glewlwydRequest("/auth/?username=" + username, "DELETE")
    .then(() => {
      var userList = this.state.userList;
      userList.forEach((user, index) => {
        if (user.username === username) {
          userList.splice(index, 1);
        }
      });
      this.setState({userList: userList});
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-login")});
    });
  }
  
  render() {
    var userList = [];
    this.state.userList.forEach((user, index) => {
      var inputUser;
      if (this.state.config.profilePicture && user[this.state.config.profilePicture.userProperty]) {
        var picData = user[this.state.config.profilePicture.userProperty];
        if (Array.isArray(picData)) {
          picData = picData[0];
        }
        inputUser = 
        <div>
          <input type="radio" className="input-hidden" onChange={() => this.handleToggleGrantScope(user)} name="select-user" id={"select-user-" + user.username} checked={selected}/>
          <label htmlFor={"select-user-" + user.username}>
            <img className="img-thumb" src={"data:"+this.state.config.profilePicture.type+";base64,"+picData} alt={this.state.config.profilePicture.userProperty} />
          </label>
        </div>
      } else {
        inputUser = <input type="radio" className="form-control" onChange={() => this.handleToggleGrantScope(user)} name="select-user" id={"select-user-" + user.username} checked={selected}/>
      }
      var selected = (user.username===this.state.currentUser.username);
      userList.push(
        <li className={"list-group-item" + (selected?" active":"")} key={index}>
          <div className="row">
            <div className="col">
              <div className="input-group mb-3">
                <div className="input-group-prepend">
                  {inputUser}
                </div>
                <div className="btn-icon-right">
                  <label className="form-check-label" htmlFor={"select-user-" + user.username}>{user.name||user.username}</label>
                </div>
              </div>
            </div>
            <div className="col text-right">
              <button type="button" className="btn btn-secondary" onClick={() => this.handleLogoutAccount(user.username)}>{i18next.t("login.logout")}</button>
            </div>
          </div>
        </li>
      );
    });
    return (
    <div>
      <div className="row">
        <div className="col-md-12">
          <h4>{i18next.t("login.select-acount-title")}</h4>
        </div>
      </div>
      <div className="row">
        <div className="col-md-12">
          <ul className="list-group">
            {userList}
          </ul>
        </div>
      </div>
      <div className="row">
        <div className="col-md-12">
          <hr/>
        </div>
      </div>
      <div className="row">
        <div className="col-md-12">
          <div className="btn-group" role="group">
            <button type="button" className="btn btn-primary" onClick={this.handleSelectAccount}>{i18next.t("login.select")}</button>
            <button type="button" className="btn btn-primary" onClick={this.handleNewAccount}>{i18next.t("login.login-another-new")}</button>
          </div>
        </div>
      </div>
      <div className="row">
        <div className="col-md-12">
          <hr/>
        </div>
      </div>
    </div>);
  }
}

export default SelectAccount;
