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
      }
    };
    
    this.fetchLists = this.fetchLists.bind(this);
    this.getTable = this.getTable.bind(this);
    
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
      var plugins = this.state.plugins;
      res.forEach((plugin) => {
        if (plugin.module === "oauth2-glewlwyd") {
          plugin.tokenList = [];
          plugins.oauth2 = plugin;
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
        {i18next.t("profile.enabled")}
      </th>
      <th>
      </th>
    </tr>;
    var sessionList = [];
    this.state.sessionList.forEach((session, index) => {
      var lastLogin = new Date(), expiration = new Date();
      lastLogin.setUTCSeconds(session.lastLogin);
      expiration.setUTCSeconds(session.expiration);
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
          {session.enabled}
        </td>
        <td>
        </td>
      </tr>
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
            {this.getTable(sessionHeader, sessionList)}
          </div>
        </div>
      </div>
    );
  }
}

export default Session;
