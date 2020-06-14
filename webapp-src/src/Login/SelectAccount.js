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
  
  componentWillReceiveProps(nextProps) {
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
    var userList = [], userPicture;
    this.state.userList.forEach((user, index) => {
      var inputUser;
      if (user.picture) {
        var picData = user.picture;
        userPicture = <img style={{width: "30px", maxHeight: "21px", objectFit: "scale-down"}} className="img-thumb" src={"data:*;base64,"+picData} />
      } else {
        userPicture = <i className="fas fa-user" style={{fontSize: "24px"}}>&nbsp;</i>;
      }
      inputUser = 
        <div className="input-group" id={"select-user-" + user.username}>
          <label style={{width: "100%", marginBottom: "0", paddingLeft: "0", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis"}}>
            <div className="col input-group-prepend" style={{display: "inline"}}>
              {userPicture}
            </div>
            <input type="radio" className="input-hidden" onChange={() => this.handleToggleGrantScope(user)} name="select-user" checked={selected} />
            <div className="col input-group-append" style={{display: "inline", paddingLeft: "0", paddingLeft: "0", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis"}}>
              <div className="col btn-icon-left" style={{display: "inline", verticalAlign: "middle", paddingLeft: "0", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis"}}>
                {user.name||user.username}
              </div>
              {/* The following invisible button contains a transparent pixel and is a hack for vertical alignment ("middle"). Pure CSS solution not found.*/}
              <button type="button" disabled={true} class="btn btn-secondary" style={{visibility: "hidden", paddingLeft: "0", paddingRight: "0"}}>
                <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z/C/HgAGgwJ/lK3Q6wAAAABJRU5ErkJggg=="/>
              </button>
            </div>
          </label>
        </div>
      var selected = (user.username===this.state.currentUser.username);
      userList.push(
        <li className={"list-group-item" + (selected?" active":"")} key={index}>
          <div className="row">
            <div className="col" style={{paddingRight: "0"}}>
              {inputUser}
            </div>
            <div className="col-auto text-right" style={{paddingLeft: "0"}}>
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
