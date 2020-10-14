import React, { Component } from 'react';
import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';

import MockPluginParams from './MockPluginParams';
import GlwdOauth2Params from './GlwdOauth2Params';
import GlwdOIDCParams from './GlwdOIDCParams';
import RegisterParams from './RegisterParams';

class APIKey extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      apiKeys: props.apiKeys,
      loggedIn: props.loggedIn,
      disableObject: false
    };
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      apiKeys: nextProps.apiKeys,
      loggedIn: nextProps.loggedIn
    });
  }
  
  addApiKey(e) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: "add", role: "apiKey"});
  }

  disableApiKey(e, apiKey) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: "delete", role: "apiKey", apiKey: apiKey});
  }

  handleChangeSearchPattern (e) {
    var users = this.state.users;
    users.searchPattern = e.target.value;
    this.setState({users: users});
  }

  searchApiKey (e) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: "search", role: "apiKey", searchPattern: this.state.users.searchPattern, offset: this.state.users.offset, limit: this.state.users.limit});
  }

  navigate(e, direction) {
    e.preventDefault();
    if (direction > 0) {
      messageDispatcher.sendMessage('App', {type: "search", role: "apiKey", searchPattern: this.state.users.searchPattern, offset: this.state.users.offset+this.state.users.limit, limit: this.state.users.limit});
    } else if (this.state.users.offset) {
      messageDispatcher.sendMessage('App', {type: "search", role: "apiKey", searchPattern: this.state.users.searchPattern, offset: this.state.users.offset-this.state.users.limit, limit: this.state.users.limit});
    }
  }

  navigatePerPage(e, limit) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: "search", role: "apiKey", pattern: this.state.users.searchPattern, offset: this.state.users.offset, limit: limit});
  }
  
  render() {
    var apiKeyList = [];
    this.state.apiKeys.list.forEach((apiKey, index) => {
      var issued_at = new Date(apiKey.issued_at * 1000);
      apiKeyList.push(
      <tr key={index} className={(!apiKey.enabled?"table-danger":"")}>
        <td>
          {apiKey.counter}
        </td>
        <td>
          {apiKey.username}
        </td>
        <td>
          {issued_at.toLocaleString()}
        </td>
        <td className="d-none d-lg-table-cell">
          {apiKey.issued_for}
        </td>
        <td className="d-none d-lg-table-cell">
          {apiKey.user_agent}
        </td>
        <td>
          <a className="dropdown-item" href="#" onClick={(e) => this.disableApiKey(e, apiKey)} alt={i18next.t("admin.delete")} disabled={!apiKey.enabled}>
            <i className="fas fa-trash btn-icon"></i>
          </a>
        </td>
      </tr>
      );
    });
		return (
    <div className="table-responsive">
      <p>{i18next.t("admin.api-key-description")}</p>
      <table className="table table-striped">
        <thead>
          <tr>
            <th colSpan="2">
              <h4>{i18next.t("admin.api-key-title")}</h4>
            </th>
            <th colSpan="4">
              <form className="form-inline d-none d-lg-block" onSubmit={(e) => this.searchApiKey(e)}>
                <div className="btn-group" role="group">
                  <button disabled={!this.state.loggedIn} type="button" className="btn btn-secondary" onClick={(e) => this.navigate(e, -1)} title={i18next.t("admin.nav-previous")} disabled={!this.state.apiKeys.offset}>
                    <i className="fas fa-backward"></i>
                  </button>
                  <div className="btn-group" role="group">
                    <button disabled={!this.state.loggedIn} id="btnGroupNavPerPage" type="button" className="btn btn-secondary dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                      {i18next.t("admin.nav-per-page")}
                    </button>
                    <div className="dropdown-menu" aria-labelledby="btnGroupNavperPage">
                      <a className={"dropdown-item" + (this.state.apiKeys.limit===10?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 10)}>10</a>
                      <a className={"dropdown-item" + (this.state.apiKeys.limit===20?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 20)}>20</a>
                      <a className={"dropdown-item" + (this.state.apiKeys.limit===50?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 50)}>50</a>
                      <a className={"dropdown-item" + (this.state.apiKeys.limit===100?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 100)}>100</a>
                    </div>
                  </div>
                  <button disabled={!this.state.loggedIn} type="button" className="btn btn-secondary" onClick={(e) => this.navigate(e, 1)} title={i18next.t("admin.nav-next")} disabled={this.state.apiKeys.limit>this.state.apiKeys.list.length}>
                    <i className="fas fa-forward"></i>
                  </button>
                  <button disabled={!this.state.loggedIn} type="button" className="btn btn-secondary" onClick={(e) => this.addApiKey(e)} title={i18next.t("admin.api-key-add")}>
                    <i className="fas fa-plus"></i>
                  </button>
                </div>
                <div className="btn-group btn-icon-right" role="group">
                  <input disabled={!this.state.loggedIn} className="form-control" type="search" placeholder={i18next.t("admin.nav-search-placeholder")} aria-label="Search" onChange={this.handleChangeSearchPattern} value={this.state.apiKeys.searchPattern||""}/>
                  <button disabled={!this.state.loggedIn} className="btn btn-secondary my-sm-0" type="submit" title={i18next.t("admin.nav-search-title")} onClick={(e) => this.searchUsers(e)}>{i18next.t("admin.nav-search")}</button>
                </div>
              </form>
              <div className="dropdown d-block d-lg-none">
                <button disabled={!this.state.loggedIn} className="btn btn-secondary dropdown-toggle" type="button" id="dropdownMenuNav" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                  <i className="fas fa-chevron-circle-down"></i>
                </button>
                <div className="dropdown-menu" aria-labelledby="dropdownMenuNav">
                  <a className="dropdown-item" href="#" onClick={(e) => this.navigate(e, -1)} alt={i18next.t("admin.nav-previous")}>
                    <i className="fas fa-backward btn-icon"></i>
                    {i18next.t("admin.nav-previous")}
                  </a>
                  <a className="dropdown-item" href="#" onClick={(e) => this.navigate(e, 1)} alt={i18next.t("admin.nav-next")}>
                    <i className="fas fa-forward btn-icon"></i>
                    {i18next.t("admin.nav-next")}
                  </a>
                  <a className="dropdown-item" href="#" onClick={(e) => this.addUser(e)} alt={i18next.t("admin.api-key-add")}>
                    <i className="fas fa-plus btn-icon"></i>
                    {i18next.t("admin.api-key-add")}
                  </a>
                </div>
              </div>
            </th>
          </tr>
          <tr>
            <th>
              {i18next.t("admin.api-key-counter")}
            </th>
            <th>
              {i18next.t("admin.api-key-username")}
            </th>
            <th>
              {i18next.t("admin.api-key-issued-at")}
            </th>
            <th className="d-none d-lg-table-cell">
              {i18next.t("admin.api-key-issued-for")}
            </th>
            <th className="d-none d-lg-table-cell">
              {i18next.t("admin.api-key-user-agent")}
            </th>
            <th>
            </th>
          </tr>
        </thead>
        <tbody>
          {apiKeyList}
          <tr>
            <td colSpan="6">
              {i18next.t("admin.nav-footer", {offset: this.state.apiKeys.offset, limit: this.state.apiKeys.limit})}
            </td>
          </tr>
        </tbody>
      </table>
      <p>{i18next.t("admin.api-key-example-description")}</p>
      <code>{i18next.t("admin.api-key-example")}</code>
    </div>
		);
  }
}

export default APIKey;
