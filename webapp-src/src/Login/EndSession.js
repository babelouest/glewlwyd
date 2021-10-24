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
      sessionList: false,
      showEndSessionIframes: false,
      endSessionIframesComplete: 0,
      revokeSession: false,
      revokeTokens: false,
      logoutIgnored: false
    };
    
    this.handleIgnoreLogout = this.handleIgnoreLogout.bind(this);
    this.setRevokeAll = this.setRevokeAll.bind(this);
    this.iframeLoaded = this.iframeLoaded.bind(this);
    
    this.getFrontchannelLogoutUrls();
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      userList: nextProps.userList||[],
      currentUser: nextProps.currentUser||[],
      pluginList: nextProps.pluginList
    });
  }
  
  getFrontchannelLogoutUrls() {
    if (this.state.config.params.sid && this.state.config.params.plugin) {
      var post_redirect_to = "";
      if (this.state.config.params.post_redirect_to) {
        post_redirect_to = "?post_redirect_to="+encodeURIComponent(this.state.config.params.post_redirect_to);
      }
      apiManager.glewlwydRequestSub("/" + this.state.config.params.plugin + "/session/" + this.state.config.params.sid + "/" + this.state.config.params.client_id + post_redirect_to)
      .then((res) => {
        this.setState({sessionList: res});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      });
    }
  }
  
  handleIgnoreLogout() {
    if (this.state.sessionList.post_redirect_to) {
      document.location = this.state.sessionList.post_redirect_to;
    } else {
      document.location = this.state.config.ProfileUrl;
    }
  }
  
  setRevokeAll(e, revokeSession, revokeTokens) {
    e.preventDefault();
    this.setState({revokeSession: revokeSession, revokeTokens: revokeTokens, showEndSessionIframes: true});
  }
  
  iframeLoaded(e, index) {
    this.setState({endSessionIframesComplete: this.state.endSessionIframesComplete+1}, () => {
      console.log("iframeLoaded", this.state.endSessionIframesComplete, this.state.sessionList.client.length);
      if (this.state.endSessionIframesComplete === this.state.sessionList.client.length) {
        this.handleRevokeTokens()
        .then(() => {
          this.handleRevokeSession()
          .then(() => {
            apiManager.glewlwydRequest("/auth/", "DELETE")
            .always(() => {
              if (this.state.sessionList.post_redirect_to) {
                document.location = this.state.sessionList.post_redirect_to;
              } else {
                messageDispatcher.sendMessage('App', {type: 'SessionClosed'});
              }
            });
          });
        });
      }
    });
  }

  handleRevokeTokens() {
    if (this.state.revokeTokens) {
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
      return Promise.all(promises);
    } else {
      return Promise.resolve(true);
    }
  }
  
  handleRevokeSession() {
    if (this.state.revokeSession) {
      return apiManager.glewlwydRequest("/profile/session/", "DELETE")
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-delete-session")});
      });
    } else {
      return Promise.resolve(true);
    }
  }

  render() {
    var messageJsx, postRedirectJsx, endSessionIframesJsx = [];
    if (this.state.showEndSessionIframes) {
      this.state.sessionList.client.forEach((client, index) => {
        var url = client.frontchannel_logout_uri + "?iss=" + this.state.sessionList.iss;
        if (client.frontchannel_logout_session_required) {
          url += "&sid=" + this.state.sessionList.sid;
        }
        endSessionIframesJsx.push(
          <iframe key={index}
                  src={url}
                  width="0"
                  height="0"
                  frameBorder="0"
                  marginHeight="0"
                  marginWidth="0"
                  onLoad={(e) => this.iframeLoaded(e, index)} />
        );
      });
      messageJsx = <h4>{i18next.t("login.end-session-message-post-redirect-ongoing")}</h4>
    } else {
      messageJsx = <h4>{i18next.t("login.end-session-message-post-redirect", {client: this.state.sessionList.client_name||this.state.sessionList.client_id})}</h4>
      if (this.state.config.params.callback_url) {
        postRedirectJsx = <h4>{i18next.t("login.end-session-message-post-redirect-url")} {this.state.config.params.callback_url}</h4>
      }
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
          {postRedirectJsx}
          {endSessionIframesJsx}
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
            <button type="button" className="btn btn-danger" onClick={(e) => this.setRevokeAll(e, false, false)}>
              <i className="fas fa-sign-out-alt btn-icon"></i>{i18next.t("login.logout")}
            </button>
            <div className="btn-group btn-icon" role="group">
              <button className="btn btn-danger dropdown-toggle" type="button" id="logoutDropdown" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              </button>
              <div className="dropdown-menu" aria-labelledby="logoutDropdown">
                <a className="dropdown-item" href="#" onClick={(e) => this.setRevokeAll(e, true, true)}>{i18next.t("login.logout-all-sessions-tokens")}</a>
                <a className="dropdown-item" href="#" onClick={(e) => this.setRevokeAll(e, true, false)}>{i18next.t("login.logout-all-sessions")}</a>
                <a className="dropdown-item" href="#" onClick={(e) => this.setRevokeAll(e, false, true)}>{i18next.t("login.logout-all-tokens")}</a>
              </div>
            </div>
          </div>
          <button type="button" className="btn btn-primary btn-icon-right" onClick={this.handleIgnoreLogout}>{i18next.t("login.ignore-logout")}</button>
        </div>
      </div>
    </div>);
  }
}

export default EndSession;
