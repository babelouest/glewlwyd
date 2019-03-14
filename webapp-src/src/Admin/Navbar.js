import React, { Component } from 'react';

import messageDispatcher from '../lib/MessageDispatcher';
import apiManager from '../lib/APIManager';

class Navbar extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      curNav: "users",
      navDropdown: false,
      loggedIn: props.loggedIn
    }

    messageDispatcher.subscribe('Navbar', (message) => {
    });
    
    this.navigate = this.navigate.bind(this);
    this.toggleLogin = this.toggleLogin.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({loggedIn: nextProps.loggedIn});
  }
  
  navigate(e, page, navDropdown) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: "nav", message: page});
    this.setState({curNav: page, navDropdown: navDropdown});
  }

  toggleLogin() {
    if (this.state.loggedIn) {
      apiManager.glewlwydRequest("/auth/", "DELETE")
      .then(() => {
        messageDispatcher.sendMessage('App', {type: 'loggedIn', loggedIn: false});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-delete-session")});
      });
    } else {
      document.location.href = this.state.config.LoginUrl + "?callback_url=" + encodeURI(document.location.href) + "&scope=" + encodeURI(this.state.config.admin_scope);
    }
  }

	render() {
		return (
    <nav className="navbar navbar-expand-lg navbar-light bg-light">
      <a className="navbar-brand" href="#">Glewlwyd</a>
      <button className="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
        <span className="navbar-toggler-icon"></span>
      </button>
      <div className="collapse navbar-collapse" id="navbarSupportedContent">
        <ul className="navbar-nav mr-auto">
          <li className={"nav-item" + (this.state.curNav==="users"?" active":"")}>
            <a className="nav-link" href="#" onClick={(e) => this.navigate(e, "users", false)}>{i18next.t("admin.menu-users")}</a>
          </li>
          <li className={"nav-item" + (this.state.curNav==="clients"?" active":"")}>
            <a className="nav-link" href="#" onClick={(e) => this.navigate(e, "clients", false)}>{i18next.t("admin.menu-clients")}</a>
          </li>
          <li className={"nav-item" + (this.state.curNav==="scopes"?" active":"")}>
            <a className="nav-link" href="#" onClick={(e) => this.navigate(e, "scopes", false)}>{i18next.t("admin.menu-scopes")}</a>
          </li>
          <li className="nav-item dropdown">
            <a className={"nav-link dropdown-toggle" + (this.state.navDropdown?" active":"")} href="#" id="navbarDropdown" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              {i18next.t("admin.menu-parameters")}
            </a>
            <div className={"dropdown-menu"} aria-labelledby="navbarDropdown">
              <a className={"dropdown-item" + (this.state.curNav==="users-mod"?" active":"")} href="#" onClick={(e) => this.navigate(e, "users-mod", true)}>{i18next.t("admin.menu-users-mod")}</a>
              <a className={"dropdown-item" + (this.state.curNav==="clients-mod"?" active":"")} href="#" onClick={(e) => this.navigate(e, "clients-mod", true)}>{i18next.t("admin.menu-clients-mod")}</a>
              <div className="dropdown-divider"></div>
              <a className={"dropdown-item" + (this.state.curNav==="auth-schemes"?" active":"")} href="#" onClick={(e) => this.navigate(e, "auth-schemes", true)}>{i18next.t("admin.menu-auth-schemes")}</a>
              <div className="dropdown-divider"></div>
              <a className={"dropdown-item" + (this.state.curNav==="plugins"?" active":"")} href="#" onClick={(e) => this.navigate(e, "plugins", true)}>{i18next.t("admin.menu-plugins")}</a>
            </div>
          </li>
        </ul>
        <form className="form-inline my-2 my-lg-0">
          <button type="button" className="btn btn-primary" onClick={this.toggleLogin}>
            <i className="fas fa-sign-in-alt btn-icon"></i>{this.state.loggedIn?i18next.t("admin.menu-logout"):i18next.t("admin.menu-login")}
          </button>
        </form>
      </div>
    </nav>
		);
	}
}

export default Navbar;
