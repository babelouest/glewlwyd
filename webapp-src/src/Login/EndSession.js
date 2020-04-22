import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';

class EndSession extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      config: props.config,
      userList: props.userList||[],
      currentUser: props.currentUser||[]
    };
    
    this.handleLogout = this.handleLogout.bind(this);
    this.handleIgnoreLogout = this.handleIgnoreLogout.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      userList: nextProps.userList||[],
      currentUser: nextProps.currentUser||[]
    });
  }
  
  handleLogout() {
    apiManager.glewlwydRequest("/auth/", "DELETE")
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-delete-session")});
    })
    .always(() => {
      if (this.state.config.params.callback_url) {
        document.location.href = this.state.config.params.callback_url;
      }
    });
  }
  
  handleIgnoreLogout() {
    document.location.href = this.state.config.params.callback_url;
  }
  
  render() {
    var ignoreLogoutButton;
    if (this.state.config.params.callback_url) {
      ignoreLogoutButton = <button type="button" className="btn btn-primary btn-icon-right" onClick={this.handleIgnoreLogout}>{i18next.t("login.ignore-logout")}</button>
    }
    return (
    <div>
      <div className="row">
        <div className="col-md-12">
          <h3>{i18next.t("login.end-session-title")}</h3>
        </div>
      </div>
      <div className="row">
        <div className="col-md-12">
          <h4>{i18next.t("login.end-session-message")}</h4>
        </div>
      </div>
      <div className="row">
        <div className="col-md-12">
          <hr/>
        </div>
      </div>
      <div className="row">
        <div className="col-md-12">
          <button type="button" className="btn btn-primary btn-icon" onClick={this.handleLogout}>
            <i className="fas fa-sign-out-alt btn-icon"></i>{i18next.t("login.logout")}
          </button>
          {ignoreLogoutButton}
        </div>
      </div>
    </div>);
  }
}

export default EndSession;
