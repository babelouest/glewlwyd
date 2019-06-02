import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

class Session extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      config: props.config,
      profile: props.profile,
      sessionList: [],
      plugins: {
        oauth2: {
        }
      },
      disableObject: false
    };
    
    this.fetchLists = this.fetchLists.bind(this);
    this.getTable = this.getTable.bind(this);
    this.disableSession = this.disableSession.bind(this);
    this.disableSessionConfirm = this.disableSessionConfirm.bind(this);
    this.disableToken = this.disableToken.bind(this);
    this.disableTokenConfirm = this.disableTokenConfirm.bind(this);
    
    this.fetchLists();
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      profile: nextProps.profile
    }, () => {
      this.fetchLists();
    });
  }
  
  fetchLists() {
    apiManager.glewlwydRequest("/profile/session")
    .then((res) => {
      this.setState({sessionList: res});
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
    });
    apiManager.glewlwydRequest("/profile/plugin")
    .then((res) => {
      res.forEach((plugin) => {
        if (plugin.module === "oauth2-glewlwyd") {
          apiManager.glewlwydRequestSub("/" + plugin.name + "/profile/token" + (this.state.config.params.delegate?"?impersonate="+this.state.config.params.delegate:""))
          .then((resPlugin) => {
            var plugins = this.state.plugins;
            plugins.oauth2[plugin.name] = resPlugin;
            this.setState({plugins: plugins});
          })
          .fail((err) => {
          });
        }
      });
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
    });
  }
  
  getTable(header, rows) {
    return (<table className="table table-responsive table-striped">
      <thead>
        {header}
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
    );
  }
  
  disableSession(session) {
    this.setState({disableObject: session}, () => {
      messageDispatcher.sendMessage('App', {type: "confirm", title: i18next.t("profile.session-disable-title"), message: i18next.t("profile.session-disable-message"), callback: this.disableSessionConfirm});
    });
  }
  
  disableSessionConfirm() {
    if (this.state.disableObject) {
      apiManager.glewlwydRequest("/profile/session/" + this.state.disableObject.session_hash, "DELETE")
      .then((res) => {
        messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.session-disabled")});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
      })
      .always(() => {
        this.fetchLists();
        this.setState({disableObject: false});
        messageDispatcher.sendMessage('App', {type: "closeConfirm"});
      });
    }
  }
  
  disableToken(type, key, token) {
    this.setState({disableObject: {type: type, key: key, token: token}}, () => {
      messageDispatcher.sendMessage('App', {type: "confirm", title: i18next.t("profile.session-disable-token-title"), message: i18next.t("profile.session-disable-token-message"), callback: this.disableTokenConfirm});
    });
  }
  
  disableTokenConfirm() {
    if (this.state.disableObject) {
      if (this.state.disableObject.type === "oauth2") {
        apiManager.glewlwydRequestSub("/" + this.state.disableObject.key + "/profile/token/" + this.state.disableObject.token.token_hash + (this.state.config.params.delegate?"?impersonate="+this.state.config.params.delegate:""), "DELETE")
        .then((res) => {
          messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.token-disabled")});
        })
        .fail(() => {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
        })
        .always(() => {
          this.fetchLists();
          this.setState({disableObject: false});
          messageDispatcher.sendMessage('App', {type: "closeConfirm"});
        });
      }
    }
  }
  
  render() {
    // Session list
    var sessionHeader =
    <tr>
      <th>
        {i18next.t("profile.session-table-last-login")}
      </th>
      <th>
        {i18next.t("profile.session-table-exiration")}
      </th>
      <th>
        {i18next.t("profile.session-table-issued-for")}
      </th>
      <th>
        {i18next.t("profile.session-table-user-agent")}
      </th>
      <th>
        {i18next.t("admin.enabled")}
      </th>
      <th>
      </th>
    </tr>;
    var sessionList = [], tokenTables = [];
    this.state.sessionList.forEach((session, index) => {
      var lastLogin = new Date(session.last_login * 1000), expiration = new Date(session.expiration * 1000);
      sessionList.push(
      <tr key={index}>
        <td>
          {lastLogin.toLocaleString()}
        </td>
        <td>
          {expiration.toLocaleString()}
        </td>
        <td>
          {session.issued_for}
        </td>
        <td>
          {session.user_agent}
        </td>
        <td>
          {session.enabled?i18next.t("profile.session-enabled-true"):i18next.t("profile.session-enabled-false")}
        </td>
        <td>
          <button type="button" className="btn btn-secondary" onClick={(e) => this.disableSession(session)} title={i18next.t("admin.delete")} disabled={!session.enabled}>
            <i className="fas fa-trash"></i>
          </button>
        </td>
      </tr>
      );
    });
    var i = 0;
    for (var key in this.state.plugins.oauth2) {
      var oauth2 = this.state.plugins.oauth2[key];
      var oauth2Header =
      <tr>
        <th>
          {i18next.t("profile.session-table-last-login")}
        </th>
        <th>
          {i18next.t("profile.session-table-exiration")}
        </th>
        <th>
          {i18next.t("profile.session-table-issued-for")}
        </th>
        <th>
          {i18next.t("profile.session-table-user-agent")}
        </th>
        <th>
          {i18next.t("admin.enabled")}
        </th>
        <th>
        </th>
      </tr>;
      var tokenList = [], tokenTables = [];
      oauth2.forEach((token, index) => {
        var lastSeen = new Date(token.last_seen * 1000), expiration = new Date(token.expires_at * 1000);
        tokenList.push(
        <tr key={index}>
          <td>
            {lastSeen.toLocaleString()}
          </td>
          <td>
            {expiration.toLocaleString()}
          </td>
          <td>
            {token.issued_for}
          </td>
          <td>
            {token.user_agent}
          </td>
          <td>
            {token.enabled?i18next.t("profile.session-enabled-true"):i18next.t("profile.session-enabled-false")}
          </td>
          <td>
            <button type="button" className="btn btn-secondary" onClick={(e) => this.disableToken("oauth2", key, token)} title={i18next.t("admin.delete")} disabled={!token.enabled}>
              <i className="fas fa-trash"></i>
            </button>
          </td>
        </tr>
        );
      });
      tokenTables.push(
        <div className="card" key={i}>
          <div className="card-header" id="dataFormatCard">
            <h2 className="mb-0">
              <button className="btn btn-link" type="button" data-toggle="collapse" data-target={"#collapseOauth2-"+key} aria-expanded="true" aria-controls={"collapseOauth2-"+key}>
                {i18next.t("profile.session-token-oauth2-table", {name: key})}
              </button>
            </h2>
          </div>
          <div id={"collapseOauth2-"+key} className="collapse" aria-labelledby="dataFormatCard" data-parent="#accordionParams">
            <div className="card-body">
              {this.getTable(oauth2Header, tokenList)}
            </div>
          </div>
        </div>
      );
      i++;
    }
    return (
      <div>
        <div className="row">
          <div className="col-md-12">
            <h4>{i18next.t("profile.session-title")}</h4>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            <div className="accordion" id="accordionParams">
              <div className="card">
                <div className="card-header" id="dataFormatCard">
                  <h2 className="mb-0">
                    <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseSession" aria-expanded="true" aria-controls="collapseSession">
                      {i18next.t("profile.session-table")}
                    </button>
                  </h2>
                </div>
                <div id="collapseSession" className="collapse" aria-labelledby="dataFormatCard" data-parent="#accordionParams">
                  <div className="card-body">
                    {this.getTable(sessionHeader, sessionList)}
                  </div>
                </div>
              </div>
              {tokenTables}
            </div>
          </div>
        </div>
      </div>
    );
  }
}

export default Session;
