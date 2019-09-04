import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';

class Clients extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      clients: props.clients
    }

    messageDispatcher.subscribe('Clients', (message) => {
    });

    this.addClient = this.addClient.bind(this);
    this.editClient = this.editClient.bind(this);
    this.deleteClient = this.deleteClient.bind(this);
    this.handleChangeSearchPattern = this.handleChangeSearchPattern.bind(this);
    this.searchClients = this.searchClients.bind(this);
    this.navigate = this.navigate.bind(this);
    this.navigatePerPage = this.navigatePerPage.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      clients: nextProps.clients
    });
  }

  addClient(e) {
    messageDispatcher.sendMessage('App', {type: "add", role: "client"});
  }

  editClient(e, client) {
    messageDispatcher.sendMessage('App', {type: "edit", role: "client", client: client});
  }

  deleteClient(e, client) {
    messageDispatcher.sendMessage('App', {type: "delete", role: "client", client: client});
  }

  handleChangeSearchPattern (e) {
    var clients = this.state.clients;
    clients.searchPattern = e.target.value;
    this.setState({clients: clients});
  }

  searchClients (e) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: "search", role: "client", searchPattern: this.state.clients.searchPattern, offset: this.state.clients.offset, limit: this.state.clients.limit});
  }

  navigate(e, direction) {
    if (direction > 0) {
      messageDispatcher.sendMessage('App', {type: "search", role: "client", searchPattern: this.state.clients.searchPattern, offset: this.state.clients.offset+this.state.clients.limit, limit: this.state.clients.limit});
    } else if (this.state.clients.offset) {
      messageDispatcher.sendMessage('App', {type: "search", role: "client", searchPattern: this.state.clients.searchPattern, offset: this.state.clients.offset-this.state.clients.limit, limit: this.state.clients.limit});
    }
  }

  navigatePerPage(e, limit) {
    messageDispatcher.sendMessage('App', {type: "search", role: "client", searchPattern: this.state.clients.searchPattern, offset: this.state.clients.offset, limit: limit});
  }
  
	render() {
    var clients = [];
    this.state.clients.list.forEach((client, index) => {
      clients.push(<tr key={index}>
        <td>{client.source}</td>
        <td>{client.client_id}</td>
        <td>{client.name||""}</td>
        <td>{(client.enabled?i18next.t("admin.yes"):i18next.t("admin.no"))}</td>
        <td>
          <div className="btn-group pull-right" role="group">
            <button type="button" className="btn btn-secondary" onClick={(e) => this.editClient(e, client)} title={i18next.t("admin.edit")}>
              <i className="fas fa-edit"></i>
            </button>
            <button type="button" className="btn btn-secondary" onClick={(e) => this.deleteClient(e, client)} title={i18next.t("admin.delete")}>
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
          <th colSpan="2">
            <h4>{i18next.t("admin.client-list-title")}</h4>
          </th>
          <th colSpan="3">
            <form className="form-inline" onSubmit={(e) => this.searchClients(e)}>
              <div className="input-group mr-sm-2">
                <input className="form-control" type="search" placeholder={i18next.t("admin.nav-search-placeholder")} aria-label="Search" onChange={this.handleChangeSearchPattern} value={this.state.clients.searchPattern||""}/>
                <button className="btn btn-secondary my-sm-0" type="submit" title={i18next.t("admin.nav-search-title")} onClick={(e) => this.searchClients(e)}>{i18next.t("admin.nav-search")}</button>
              </div>
              <div className="btn-group" role="group">
                <button type="button" className="btn btn-secondary" onClick={(e) => this.navigate(e, -1)} title={i18next.t("admin.nav-previous")} disabled={!this.state.clients.offset}>
                  <i className="fas fa-backward"></i>
                </button>
                <div className="btn-group" role="group">
                  <button id="btnGroupNavPerPage" type="button" className="btn btn-secondary dropdown-toggle" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                    {i18next.t("admin.nav-per-page")}
                  </button>
                  <div className="dropdown-menu" aria-labelledby="btnGroupNavperPage">
                    <a className={"dropdown-item" + (this.state.clients.limit===10?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 10)}>10</a>
                    <a className={"dropdown-item" + (this.state.clients.limit===20?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 20)}>20</a>
                    <a className={"dropdown-item" + (this.state.clients.limit===50?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 50)}>50</a>
                    <a className={"dropdown-item" + (this.state.clients.limit===100?" active":"")} href="#" onClick={(e) => this.navigatePerPage(e, 100)}>100</a>
                  </div>
                </div>
                <button type="button" className="btn btn-secondary" onClick={(e) => this.navigate(e, 1)} title={i18next.t("admin.nav-next")}>
                  <i className="fas fa-forward"></i>
                </button>
                <button type="button" className="btn btn-secondary" onClick={(e) => this.addClient(e)} title={i18next.t("admin.client-add")}>
                  <i className="fas fa-plus"></i>
                </button>
              </div>
            </form>
          </th>
        </tr>
        <tr>
          <th>
            {i18next.t("admin.source")}
          </th>
          <th>
            {i18next.t("admin.client_id")}
          </th>
          <th>
            {i18next.t("admin.name")}
          </th>
          <th>
            {i18next.t("admin.enabled")}
          </th>
          <th>
          </th>
        </tr>
      </thead>
      <tbody>
        {clients}
        <tr>
          <td colSpan="5">
            {i18next.t("admin.nav-footer", {offset: this.state.clients.offset, limit: this.state.clients.limit})}
          </td>
        </tr>
      </tbody>
    </table>
		);
	}
}

export default Clients;
