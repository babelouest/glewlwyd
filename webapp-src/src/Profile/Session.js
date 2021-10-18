import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import Notification from '../lib/Notification';

class Session extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      config: props.config,
      sessionList: props.sessionList,
      plugins: props.plugins,
      clientGrantList: props.clientGrantList,
      disableObject: false,
      removeClientScope: false,
      showActive: false
    };
    
    this.getTable = this.getTable.bind(this);
    this.disableSession = this.disableSession.bind(this);
    this.disableSessionConfirm = this.disableSessionConfirm.bind(this);
    this.disableToken = this.disableToken.bind(this);
    this.disableTokenConfirm = this.disableTokenConfirm.bind(this);
    this.toggleActive = this.toggleActive.bind(this);
    this.removeClientScopeGrant = this.removeClientScopeGrant.bind(this);
    this.removeClientScopeGrantConfirm = this.removeClientScopeGrantConfirm.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      plugins: nextProps.plugins,
      sessionList: nextProps.sessionList,
      clientGrantList: nextProps.clientGrantList
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
  
  toggleActive() {
    this.setState({showActive: !this.state.showActive});
  }
  
  disableSessionConfirm(result) {
    if (result) {
      if (this.state.disableObject !== null) {
        apiManager.glewlwydRequest("/profile/session/" + this.state.disableObject.session_hash, "DELETE")
        .then((res) => {
          messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.session-disabled")});
        })
        .fail((err) => {
          if (err.status === 401) {
            messageDispatcher.sendMessage('App', {type: "loggedIn", loggedIn: false});
          } else {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
          }
        })
        .always(() => {
          messageDispatcher.sendMessage('App', {type: "refreshSession"});
          this.setState({disableObject: false});
        });
      } else {
        apiManager.glewlwydRequest("/profile/session/", "DELETE")
        .then((res) => {
          messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.session-disabled")});
        })
        .fail((err) => {
          if (err.status === 401) {
            messageDispatcher.sendMessage('App', {type: "loggedIn", loggedIn: false});
          } else {
            messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
          }
        })
        .always(() => {
          messageDispatcher.sendMessage('App', {type: "refreshSession"});
          this.setState({disableObject: false});
        });
      }
    }
    messageDispatcher.sendMessage('App', {type: "closeConfirm"});
  }
  
  disableToken(type, key, token) {
    this.setState({disableObject: {type: type, key: key, token: token}}, () => {
      messageDispatcher.sendMessage('App', {type: "confirm", title: i18next.t("profile.session-disable-token-title"), message: (token?i18next.t("profile.session-disable-token-message"):i18next.t("profile.session-disable-all-token-message")), callback: this.disableTokenConfirm});
    });
  }
  
  disableTokenConfirm(result) {
    if (result) {
      if (this.state.disableObject) {
        if (this.state.disableObject.type === "oauth2") {
          apiManager.glewlwydRequestSub("/" + this.state.disableObject.key + "/profile/token/" + (this.state.disableObject.token?this.state.disableObject.token.token_hash:"") + (this.state.config.params.delegate?"?impersonate="+this.state.config.params.delegate:""), "DELETE")
          .then((res) => {
            messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.token-disabled")});
          })
          .fail((err) => {
            if (err.status === 401) {
              messageDispatcher.sendMessage('App', {type: "loggedIn", loggedIn: false});
            } else {
              messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
            }
          })
          .always(() => {
            messageDispatcher.sendMessage('App', {type: "refreshSession"});
            this.setState({disableObject: false});
            messageDispatcher.sendMessage('App', {type: "closeConfirm"});
          });
        } else if (this.state.disableObject.type === "oidc") {
          apiManager.glewlwydRequestSub("/" + this.state.disableObject.key + "/token/" + (this.state.disableObject.token?this.state.disableObject.token.token_hash:"") + (this.state.config.params.delegate?"?impersonate="+this.state.config.params.delegate:""), "DELETE")
          .then((res) => {
            messageDispatcher.sendMessage('Notification', {type: "info", message: i18next.t("profile.token-disabled")});
          })
          .fail((err) => {
            if (err.status === 401) {
              messageDispatcher.sendMessage('App', {type: "loggedIn", loggedIn: false});
            } else {
              messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("error-api-connect")});
            }
          })
          .always(() => {
            messageDispatcher.sendMessage('App', {type: "refreshSession"});
            this.setState({disableObject: false});
          });
        }
      }
    }
    messageDispatcher.sendMessage('App', {type: "closeConfirm"});
  }
  
  removeClientScopeGrant(e, client_id, scope) {
    this.setState({removeClientScope: {client_id: client_id, scope: scope}}, () => {
      messageDispatcher.sendMessage('App', {type: "confirm", title: i18next.t("profile.session-remove-scope-grant-title"), message: i18next.t("profile.session-remove-scope-grant-message"), callback: this.removeClientScopeGrantConfirm});
    });
  }
  
  removeClientScopeGrantConfirm(result) {
    if (result) {
      var scopeList = [], found = false;
      this.state.clientGrantList.forEach(clientGrant => {
        if (clientGrant.client_id === this.state.removeClientScope.client_id) {
          found = true;
          clientGrant.scope.forEach(scope => {
            if (scope.name !== this.state.removeClientScope.scope) {
              scopeList.push(scope.name);
            }
          });
        }
      });
      if (found) {
        apiManager.glewlwydRequest("/auth/grant/" + encodeURIComponent(this.state.removeClientScope.client_id), "PUT", {scope: scopeList.join(" ")})
        .then(() => {
          messageDispatcher.sendMessage('App', {type: 'refreshClientGrant'});
        })
        .fail(() => {
          messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-set-grant")});
        });
      }
    }
    messageDispatcher.sendMessage('App', {type: "closeConfirm"});
  }
  
  render() {
    // Session list
    var sessionHeader =
      <tr>
        <th>
          {i18next.t("profile.session-table-last-login")}
        </th>
        <th>
          {i18next.t("profile.session-table-expiration")}
        </th>
        <th className="d-none d-lg-table-cell">
          {i18next.t("profile.session-table-issued-for")}
        </th>
        <th className="d-none d-lg-table-cell">
          {i18next.t("profile.session-table-user-agent")}
        </th>
        <th>
          <div className="form-check">
            <input className="form-check-input" type="checkbox" onChange={this.toggleActive} checked={this.state.showActive} id="session-table"/>
            <label className="form-check-label" htmlFor="session-table">
              {i18next.t("admin.enabled")}
            </label>
          </div>
        </th>
        <th>
          <button type="button" className="btn btn-secondary" onClick={(e) => this.disableSession(null)} title={i18next.t("admin.delete-all")}>
            <i className="fas fa-trash"></i>
          </button>
        </th>
      </tr>;
    var sessionList = [], tokenTables = [], curDate = new Date();
    this.state.sessionList.forEach((session, index) => {
      var lastLogin = new Date(session.last_login * 1000), expiration = new Date(session.expiration * 1000);
      if (!this.state.showActive || (expiration >= curDate && session.enabled)) {
        sessionList.push(
        <tr key={index}>
          <td>
            {lastLogin.toLocaleString()}
          </td>
          <td>
            {expiration.toLocaleString()}
          </td>
          <td className="d-none d-lg-table-cell">
            {session.issued_for}
          </td>
          <td className="d-none d-lg-table-cell">
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
      }
    });
    var i = 0;
    var tokenTables = [];
    for (var oauthKey in this.state.plugins.oauth2) {
      var oauth2 = this.state.plugins.oauth2[oauthKey];
      var oauth2Header =
      <tr>
        <th>
          {i18next.t("profile.session-table-last-login")}
        </th>
        <th>
          {i18next.t("profile.session-table-expiration")}
        </th>
        <th className="d-none d-lg-table-cell">
          {i18next.t("profile.session-table-client")}
        </th>
        <th className="d-none d-lg-table-cell">
          {i18next.t("profile.session-table-issued-for")}
        </th>
        <th className="d-none d-lg-table-cell">
          {i18next.t("profile.session-table-user-agent")}
        </th>
        <th>
          <div className="form-check">
            <input className="form-check-input" type="checkbox" onChange={this.toggleActive} checked={this.state.showActive} id="session-table"/>
            <label className="form-check-label" htmlFor="session-table">
              {i18next.t("admin.enabled")}
            </label>
          </div>
        </th>
        <th>
          <button type="button" className="btn btn-secondary" onClick={(e) => this.disableToken("oauth2", oauthKey, null)} title={i18next.t("admin.delete-all")}>
            <i className="fas fa-trash"></i>
          </button>
        </th>
      </tr>;
      var tokenList = [];
      oauth2.forEach((token, index) => {
        var lastSeen = new Date(token.last_seen * 1000), expiration = new Date(token.expires_at * 1000);
        if (!this.state.showActive || (expiration >= curDate && token.enabled)) {
          tokenList.push(
          <tr key={index}>
            <td>
              {lastSeen.toLocaleString()}
            </td>
            <td>
              {expiration.toLocaleString()}
            </td>
            <td className="d-none d-lg-table-cell">
              {token.client_id}
            </td>
            <td className="d-none d-lg-table-cell">
              {token.issued_for}
            </td>
            <td className="d-none d-lg-table-cell">
              {token.user_agent}
            </td>
            <td>
              {token.enabled?i18next.t("profile.session-enabled-true"):i18next.t("profile.session-enabled-false")}
            </td>
            <td>
              <button type="button" className="btn btn-secondary" onClick={(e) => this.disableToken("oauth2", oauthKey, token)} title={i18next.t("admin.delete")} disabled={!token.enabled}>
                <i className="fas fa-trash"></i>
              </button>
            </td>
          </tr>
          );
        }
      });
      tokenTables.push(
        <div className="card" key={++i}>
          <div className="card-header" id="dataFormatCard">
            <h2 className="mb-0">
              <button className="btn btn-link" type="button" data-toggle="collapse" data-target={"#collapseOauth2-"+oauthKey} aria-expanded="true" aria-controls={"collapseOauth2-"+oauthKey}>
                {i18next.t("profile.session-token-oauth2-table", {name: oauthKey})}
              </button>
            </h2>
          </div>
          <div id={"collapseOauth2-"+oauthKey} className="collapse" aria-labelledby="dataFormatCard" data-parent="#accordionParams">
            <div className="card-body">
              {this.getTable(oauth2Header, tokenList)}
            </div>
          </div>
        </div>
      );
    }
    i = tokenTables.length;
    for (var oidcKey in this.state.plugins.oidc) {
      var oidc = this.state.plugins.oidc[oidcKey];
      var oidcHeader =
      <tr>
        <th>
          {i18next.t("profile.session-table-last-login")}
        </th>
        <th>
          {i18next.t("profile.session-table-expiration")}
        </th>
        <th className="d-none d-lg-table-cell">
          {i18next.t("profile.session-table-client")}
        </th>
        <th className="d-none d-lg-table-cell">
          {i18next.t("profile.session-table-issued-for")}
        </th>
        <th className="d-none d-lg-table-cell">
          {i18next.t("profile.session-table-user-agent")}
        </th>
        <th>
          <div className="form-check">
            <input className="form-check-input" type="checkbox" onChange={this.toggleActive} checked={this.state.showActive} id="session-table"/>
            <label className="form-check-label" htmlFor="session-table">
              {i18next.t("admin.enabled")}
            </label>
          </div>
        </th>
        <th>
          <button type="button" className="btn btn-secondary" onClick={(e) => this.disableToken("oidc", oidcKey, null)} title={i18next.t("admin.delete-all")}>
            <i className="fas fa-trash"></i>
          </button>
        </th>
      </tr>;
      var tokenList = [];
      oidc.forEach((token, index) => {
        var lastSeen = new Date(token.last_seen * 1000), expiration = new Date(token.expires_at * 1000);
        if (!this.state.showActive || (expiration >= curDate && token.enabled)) {
          tokenList.push(
          <tr key={index}>
            <td>
              {lastSeen.toLocaleString()}
            </td>
            <td>
              {expiration.toLocaleString()}
            </td>
            <td className="d-none d-lg-table-cell">
              {token.client_id}
            </td>
            <td className="d-none d-lg-table-cell">
              {token.issued_for}
            </td>
            <td className="d-none d-lg-table-cell">
              {token.user_agent}
            </td>
            <td>
              {token.enabled?i18next.t("profile.session-enabled-true"):i18next.t("profile.session-enabled-false")}
            </td>
            <td>
              <button type="button" className="btn btn-secondary" onClick={(e) => this.disableToken("oidc", oidcKey, token)} title={i18next.t("admin.delete")} disabled={!token.enabled}>
                <i className="fas fa-trash"></i>
              </button>
            </td>
          </tr>
          );
        }
      });
      tokenTables.push(
        <div className="card" oidcKey={++i}>
          <div className="card-header" id="dataFormatCard">
            <h2 className="mb-0">
              <button className="btn btn-link" type="button" data-toggle="collapse" data-target={"#collapseOauth2-"+oidcKey} aria-expanded="true" aria-controls={"collapseOauth2-"+oidcKey}>
                {i18next.t("profile.session-token-oidc-table", {name: oidcKey})}
              </button>
            </h2>
          </div>
          <div id={"collapseOauth2-"+oidcKey} className="collapse" aria-labelledby="dataFormatCard" data-parent="#accordionParams">
            <div className="card-body">
              {this.getTable(oidcHeader, tokenList)}
            </div>
          </div>
        </div>
      );
    }
    var clientGrantList = [];
    this.state.clientGrantList.forEach((clientGrant, index) => {
      var scopeList = [];
      clientGrant.scope.forEach((scope, scopeIndex) => {
        scopeList.push(
          <div key={scopeIndex}>
            <hr/>
            <h5>
              {i18next.t("login.scheme-list-scope", {scope: (scope.display_name || scope.name)})}
              <button type="button"  className="btn btn-secondary btn-sm btn-icon-right" disabled={"openid"===scope.name} onClick={(e) => this.removeClientScopeGrant(e, clientGrant.client_id, scope.name)}>
                <i className="fas fa-trash"></i>
              </button>
            </h5>
            <p>{scope.description}</p>
          </div>
        );
      });
      clientGrantList.push(
        <div key={index}>
          <div className="alert alert-success" role="alert">
            <h4>{clientGrant.name || clientGrant.client_id}</h4>
            <hr/>
            <p>{clientGrant.description}</p>
          </div>
          {scopeList}
          <hr/>
        </div>
      );
    });
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
                    <button className="btn btn-link" type="button" data-toggle="collapse" data-target="#collapseClientGrant" aria-expanded="true" aria-controls="collapseClientGrant">
                      {i18next.t("profile.session-client-grant-table")}
                    </button>
                  </h2>
                </div>
                <div id="collapseClientGrant" className="collapse" aria-labelledby="dataFormatCard" data-parent="#accordionParams">
                  <div className="card-body">
                    {clientGrantList}
                  </div>
                </div>
              </div>
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
