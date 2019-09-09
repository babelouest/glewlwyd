import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class Scopes extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      scopes: props.scopes,
      curScope: {},
      add: false,
      searchPattern: "",
      offset: 0,
      limit: 20
    }

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
    this.setState({searchPattern: e.target.value});
  }

  searchScopes (e) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: "search", role: "scope", searchPattern: this.state.searchPattern, offset: this.state.offset, limit: this.state.limit});
  }

  navigate(e, direction) {
    if (direction > 0) {
      messageDispatcher.sendMessage('App', {type: "search", role: "scope", searchPattern: this.state.searchPattern, offset: this.state.offset+this.state.limit, limit: this.state.limit});
    } else if (this.state.offset) {
      messageDispatcher.sendMessage('App', {type: "search", role: "scope", searchPattern: this.state.searchPattern, offset: this.state.offset-this.state.limit, limit: this.state.limit});
    }
  }

  navigatePerPage(e, limit) {
    messageDispatcher.sendMessage('App', {type: "search", role: "scope", searchPattern: this.state.searchPattern, offset: this.state.offset, limit: limit});
  }
  
	render() {
    var scopes = [];
    this.state.scopes.list.forEach((scope, index) => {
      scopes.push(<tr key={index}>
        <td>{scope.name}</td>
        <td className="d-none d-lg-table-cell">{scope.display_name||""}</td>
        <td className="d-none d-lg-table-cell">{scope.description||""}</td>
        <td>
          <div className="btn-group" role="group">
            <button type="button" className="btn btn-secondary" onClick={(e) => this.editScope(e, scope)} title={i18next.t("admin.edit")}>
              <i className="fas fa-edit"></i>
            </button>
            <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteScope(e, scope)} title={i18next.t("admin.delete")}>
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
            <form className="form-inline d-none d-lg-block" onSubmit={(e) => this.searchScopes(e)}>
              <div className="btn-group" role="group">
                <button type="button" className="btn btn-secondary" onClick={(e) => this.navigate(e, -1)} title={i18next.t("admin.nav-previous")} disabled={!this.state.offset}>
                  <i className="fas fa-backward"></i>
                </button>
                <div className="btn-group" role="group">
                  <button id="btnGroupNavPerPage" type="button" className="btn btn-secondary dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    {i18next.t("admin.nav-per-page")}
                  </button>
                  <div className="dropdown-menu" aria-labelledby="btnGroupNavperPage">
                    <a className={"dropdown-item" + (this.state.limit===10?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 10)}>10</a>
                    <a className={"dropdown-item" + (this.state.limit===20?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 20)}>20</a>
                    <a className={"dropdown-item" + (this.state.limit===50?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 50)}>50</a>
                    <a className={"dropdown-item" + (this.state.limit===100?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 100)}>100</a>
                  </div>
                </div>
                <button type="button" className="btn btn-secondary" onClick={(e) => this.navigate(e, 1)} title={i18next.t("admin.nav-next")}>
                  <i className="fas fa-forward"></i>
                </button>
                <button type="button" className="btn btn-secondary" onClick={(e) => this.addScope(e)} title={i18next.t("admin.scope-add")}>
                  <i className="fas fa-plus"></i>
                </button>
              </div>
              <div className="btn-group btn-icon-right" role="group">
                <input className="form-control" type="search" placeholder={i18next.t("admin.nav-search-placeholder")} aria-label="Search" onChange={this.handleChangeSearchPattern} value={this.state.handleChangeSearchPattern}/>
                <button className="btn btn-secondary my-sm-0" type="submit" title={i18next.t("admin.nav-search-title")} onClick={(e) => this.searchScopes(e)}>{i18next.t("admin.nav-search")}</button>
              </div>
            </form>
            <div className="dropdown d-block d-lg-none">
              <button className="btn btn-secondary dropdown-toggle" type="button" id="dropdownMenuNav" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
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
                <a className="dropdown-item" href="#" onClick={(e) => this.addScope(e)} alt={i18next.t("admin.scope-add")}>
                  <i className="fas fa-plus btn-icon"></i>
                  {i18next.t("admin.scope-add")}
                </a>
              </div>
            </div>
          </th>
        </tr>
        <tr>
          <th>
            {i18next.t("admin.name")}
          </th>
          <th className="d-none d-lg-table-cell">
            {i18next.t("admin.display-name")}
          </th>
          <th className="d-none d-lg-table-cell">
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
            {i18next.t("admin.nav-footer", {offset: this.state.offset, limit: this.state.limit})}
          </td>
        </tr>
      </tbody>
    </table>
		);
	}
}

export default Scopes;
