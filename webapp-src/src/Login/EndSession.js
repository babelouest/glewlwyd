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
      currentUser: props.currentUser||[],
      pluginList: props.pluginList,
      singleLogout: props.singleLogout
    };
    
    this.handleLogout = this.handleLogout.bind(this);
    this.handleIgnoreLogout = this.handleIgnoreLogout.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      userList: nextProps.userList||[],
      currentUser: nextProps.currentUser||[],
      pluginList: nextProps.pluginList,
      singleLogout: nextProps.singleLogout
    });
  }
  
  handleLogout() {
    if (this.state.singleLogout) {
      var promises = [];
      this.state.pluginList.forEach((plugin) => {
        if (plugin.module === "oauth2-glewlwyd") {
          promises.push(apiManager.glewlwydRequestSub("/" + plugin.name + "/profile/token/", "DELETE")
          .fail(() => {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-delete-session")});
          }));
        } else if (plugin.module === "oidc") {
          promises.push(apiManager.glewlwydRequestSub("/" + plugin.name + "/token/", "DELETE")
          .fail(() => {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-delete-session")});
          }));
        }
      });
      Promise.all(promises)
      .then((res) => {
        apiManager.glewlwydRequest("/profile/session/", "DELETE")
        .then((res) => {
          apiManager.glewlwydRequest("/auth/", "DELETE")
          .always((res) => {
            if (this.state.config.params.callback_url) {
              document.location.href = this.state.config.params.callback_url;
            } else {
              messageDispatcher.sendMessage('App', {type: 'SessionClosed'});
            }
          });
        })
        .fail(() => {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-delete-session")});
        });
      })
    } else {
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
  }
  
  handleIgnoreLogout() {
    document.location.href = this.state.config.params.callback_url;
  }
  
  revokeAll(e, session, token) {
    e.preventDefault();
    var promises = [];
    if (token) {
      this.state.pluginList.forEach((plugin) => {
        if (plugin.module === "oauth2-glewlwyd") {
          promises.push(apiManager.glewlwydRequestSub("/" + plugin.name + "/profile/token/", "DELETE")
          .fail(() => {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-delete-session")});
          }));
        } else if (plugin.module === "oidc") {
          promises.push(apiManager.glewlwydRequestSub("/" + plugin.name + "/token/", "DELETE")
          .fail(() => {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-delete-session")});
          }));
        }
      });
    }
    if (promises.length) {
      Promise.all(promises)
      .then((res) => {
        if (session) {
          if (this.state.config.params.callback_url) {
            document.location.href = this.state.config.params.callback_url;
          } else {
            messageDispatcher.sendMessage('App', {type: 'SessionClosed'});
          }
          return apiManager.glewlwydRequest("/profile/session/", "DELETE")
          .then(() => {
            return apiManager.glewlwydRequest("/auth/", "DELETE");
          });
        } else {
          return res;
        }
      })
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("login.logout-all-success")});
      });
    } else if (session) {
      apiManager.glewlwydRequest("/profile/session/", "DELETE")
      .then(() => {
        return apiManager.glewlwydRequest("/auth/", "DELETE");
      })
      .then(() => {
        messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("login.logout-all-success")});
        if (this.state.config.params.callback_url) {
          document.location.href = this.state.config.params.callback_url;
        } else {
          messageDispatcher.sendMessage('App', {type: 'SessionClosed'});
        }
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-delete-session")});
      });
    }
  }

  render() {
    var ignoreLogoutButton, lgoutAllButton, messageJsx;
    if (this.state.config.params.callback_url) {
      ignoreLogoutButton = <button type="button" className="btn btn-primary btn-icon-right" onClick={this.handleIgnoreLogout}>{i18next.t("login.ignore-logout")}</button>
    }
    if (!this.state.singleLogout) {
      lgoutAllButton = 
        <div className="btn-group btn-icon" role="group">
          <button className="btn btn-danger dropdown-toggle" type="button" id="logoutDropdown" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
          </button>
          <div className="dropdown-menu" aria-labelledby="logoutDropdown">
            <a className="dropdown-item" href="#" onClick={(e) => this.revokeAll(e, true, true)}>{i18next.t("login.logout-all-sessions-tokens")}</a>
            <a className="dropdown-item" href="#" onClick={(e) => this.revokeAll(e, true, false)}>{i18next.t("login.logout-all-sessions")}</a>
            <a className="dropdown-item" href="#" onClick={(e) => this.revokeAll(e, false, true)}>{i18next.t("login.logout-all-tokens")}</a>
          </div>
        </div>
      messageJsx = <h4>{i18next.t("login.end-session-message")}</h4>
    } else {
      messageJsx = <h4>{i18next.t("login.end-all-session-message")}</h4>
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
          {messageJsx}
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
            <button type="button" className="btn btn-danger" onClick={this.handleLogout}>
              <i className="fas fa-sign-out-alt btn-icon"></i>{i18next.t("login.logout")}
            </button>
            {lgoutAllButton}
          </div>
          {ignoreLogoutButton}
        </div>
      </div>
    </div>);
  }
}

export default EndSession;
