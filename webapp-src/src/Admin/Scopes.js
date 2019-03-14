import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class Scopes extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      scopes: props.scopes
    }

    messageDispatcher.subscribe('Scopes', (message) => {
    });

    this.addScope = this.addScope.bind(this);
    this.editScope = this.editScope.bind(this);
    this.deleteScope = this.deleteScope.bind(this);
    this.handleChangeSearchPattern = this.handleChangeSearchPattern.bind(this);
    this.searchScopes = this.searchScopes.bind(this);
    this.navigate = this.navigate.bind(this);
    this.navigatePerPage = this.navigatePerPage.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      scopes: nextProps.scopes
    });
  }

  addScope(e) {
    messageDispatcher.sendMessage('App', {type: "add", role: "scope"});
  }

  editScope(e, scope) {
    messageDispatcher.sendMessage('App', {type: "edit", role: "scope", scope: scope});
  }

  deleteScope(e, scope) {
    messageDispatcher.sendMessage('App', {type: "delete", role: "scope", scope: scope});
  }

  handleChangeSearchPattern (e) {
    var scopes = this.state.scopes;
    scopes.pattern = e.target.value;
    this.setState({scopes: scopes});
  }

  searchScopes (e) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: "search", role: "scope", pattern: this.state.scopes.pattern, offset: this.state.scopes.offset, limit: this.state.scopes.limit});
  }

  navigate(e, direction) {
    if (direction > 0) {
      messageDispatcher.sendMessage('App', {type: "search", role: "scope", pattern: this.state.scopes.pattern, offset: this.state.scopes.offset+this.state.scopes.limit, limit: this.state.scopes.limit});
    } else if (this.state.scopes.offset) {
      messageDispatcher.sendMessage('App', {type: "search", role: "scope", pattern: this.state.scopes.pattern, offset: this.state.scopes.offset-this.state.scopes.limit, limit: this.state.scopes.limit});
    }
  }

  navigatePerPage(e, limit) {
    messageDispatcher.sendMessage('App', {type: "search", role: "scope", pattern: this.state.scopes.pattern, offset: this.state.scopes.offset, limit: limit});
  }
  
	render() {
    var scopes = [];
    this.state.scopes.list.forEach((scope, index) => {
      scopes.push(<tr key={index}>
        <td>{scope.name}</td>
        <td>{scope.display_name||""}</td>
        <td>{scope.description||""}</td>
        <td>
          <div className="btn-group" role="group">
            <button type="button" className="btn btn-secondary" onClick={(e) => this.editScope(e, scope)} title={i18next.t("admin.scope-edit")}>
              <i className="fas fa-edit"></i>
            </button>
            <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteScope(e, scope)} title={i18next.t("admin.scope-delete")}>
              <i className="fas fa-trash"></i>
            </button>
          </div>
        </td>
      </tr>);
    });
		return (
    <table className="table table-responsive table-striped">
      <thead>
        <tr>
          <th colSpan="1">
            <h4>{i18next.t("admin.scope-list-title")}</h4>
          </th>
          <th colSpan="3">
            <form className="form-inline" onSubmit={(e) => this.searchScopes(e)}>
              <div className="input-group mr-sm-2">
                <input className="form-control" type="search" placeholder={i18next.t("admin.nav-search-placeholder")} aria-label="Search" onChange={this.handleChangeSearchPattern} value={this.state.scopes.pattern||""}/>
                <button className="btn btn-secondary my-sm-0" type="submit" title={i18next.t("admin.nav-search-title")} onClick={(e) => this.searchScopes(e)}>{i18next.t("admin.nav-search")}</button>
              </div>
              <div className="btn-group" role="group">
                <button type="button" className="btn btn-secondary" onClick={(e) => this.navigate(e, -1)} title={i18next.t("admin.nav-previous")} disabled={!this.state.scopes.offset}>
                  <i className="fas fa-backward"></i>
                </button>
                <div className="btn-group" role="group">
                  <button id="btnGroupNavPerPage" type="button" className="btn btn-secondary dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    {i18next.t("admin.nav-per-page")}
                  </button>
                  <div className="dropdown-menu" aria-labelledby="btnGroupNavperPage">
                    <a className={"dropdown-item" + (this.state.scopes.limit===10?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 10)}>10</a>
                    <a className={"dropdown-item" + (this.state.scopes.limit===20?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 20)}>20</a>
                    <a className={"dropdown-item" + (this.state.scopes.limit===50?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 50)}>50</a>
                    <a className={"dropdown-item" + (this.state.scopes.limit===100?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 100)}>100</a>
                  </div>
                </div>
                <button type="button" className="btn btn-secondary" onClick={(e) => this.navigate(e, 1)} title={i18next.t("admin.nav-next")}>
                  <i className="fas fa-forward"></i>
                </button>
                <button type="button" className="btn btn-secondary" onClick={(e) => this.addScope(e)} title={i18next.t("admin.scope-add")}>
                  <i className="fas fa-plus"></i>
                </button>
              </div>
            </form>
          </th>
        </tr>
        <tr>
          <th>
            {i18next.t("admin.name")}
          </th>
          <th>
            {i18next.t("admin.displayName")}
          </th>
          <th>
            {i18next.t("admin.description")}
          </th>
          <th>
          </th>
        </tr>
      </thead>
      <tbody>
        {scopes}
        <tr>
          <td colSpan="6">
            {i18next.t("admin.nav-footer", {offset: this.state.scopes.offset, limit: this.state.scopes.limit})}
          </td>
        </tr>
      </tbody>
    </table>
		);
	}
}

export default Scopes;
