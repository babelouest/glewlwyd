import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';

class CibaMessage extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      config: props.config,
      ciba_message: props.ciba_message
    };
    
    this.handleLogout = this.handleLogout.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      ciba_message: nextProps.ciba_message
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
      } else {
        messageDispatcher.sendMessage('App', {type: 'SessionClosed'});
      }
    });
  }
  
  render() {
    var message;
    if (this.state.ciba_message === "complete") {
      message = i18next.t("login.ciba-message-message-complete")
    } else if (this.state.ciba_message === "invalid") {
      message = i18next.t("login.ciba-message-message-invalid")
    } else if (this.state.ciba_message === "not_found") {
      message = i18next.t("login.ciba-message-message-not-found")
    } else if (this.state.ciba_message === "server_error") {
      message = i18next.t("login.ciba-message-message-server-error")
    } else if (this.state.ciba_message === "cancelled") {
      message = i18next.t("login.ciba-message-message-cancelled")
    }
    return (
    <div>
      <div className="row">
        <div className="col-md-12">
          <h3>{i18next.t("login.ciba-message-title")}</h3>
        </div>
      </div>
      <div className="row">
        <div className="col-md-12">
          <h4>{message}</h4>
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
        </div>
      </div>
    </div>);
  }
}

export default CibaMessage;
