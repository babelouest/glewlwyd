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
      profileList: props.profileList,
      loggedIn: props.loggedIn
    }

    messageDispatcher.subscribe('Navbar', (message) => {
    });
    
    this.navigate = this.navigate.bind(this);
    this.toggleLogin = this.toggleLogin.bind(this);
    this.changeLang = this.changeLang.bind(this);
    this.changeProfile = this.changeProfile.bind(this);
  }

  componentWillReceiveProps(nextProps) {
    this.setState({loggedIn: nextProps.loggedIn, profileList: nextProps.profileList});
  }
  
  navigate(e, page, navDropdown) {
    e.preventDefault();
    messageDispatcher.sendMessage('App', {type: "nav", message: page});
    this.setState({curNav: page, navDropdown: navDropdown});
  }

  toggleLogin() {
    if (this.state.loggedIn) {
      apiManager.glewlwydRequest("/auth/?username=" + encodeURI(this.state.profileList[0].username), "DELETE")
      .then(() => {
        messageDispatcher.sendMessage('App', {type: 'loggedIn', loggedIn: false});
      })
      .fail(() => {
        messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-delete-session")});
      });
    } else {
      var schemeDefault = "";
      this.state.config.sessionSchemes.forEach((scheme) => {
        if (scheme.scheme_default) {
          scheme.scheme_default.forEach((page) => {
            if (page === "admin") {
              schemeDefault = scheme.scheme_name;
            }
          });
        }
      });
      document.location.href = this.state.config.LoginUrl + "?callback_url=" + encodeURI([location.protocol, '//', location.host, location.pathname].join('')) + "&scope=" + encodeURI(this.state.config.admin_scope) + "&scheme=" + encodeURI(schemeDefault);
    }
  }

  changeLang(e, lang) {
    i18next.changeLanguage(lang)
    .then(() => {
      this.setState({lang: lang});
      messageDispatcher.sendMessage('App', {type: "lang"});
    });
  }

  changeProfile(e, profile) {
    apiManager.glewlwydRequest("/auth/", "POST", {username: profile.username})
    .then(() => {
      messageDispatcher.sendMessage('App', {type: "profile"});
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-login")});
    });
  }

	render() {
    var langList = [], profileList = [], profileDropdown;
    ["en","fr"].forEach((lang, i) => {
      if (lang === i18next.language) {
        langList.push(<a className="dropdown-item active" href="#" key={i}>{lang}</a>);
      } else {
        langList.push(<a className="dropdown-item" href="#" onClick={(e) => this.changeLang(e, lang)} key={i}>{lang}</a>);
      }
    });
    if (this.state.profileList) {
      this.state.profileList.forEach((profile, index) => {
        profileList.push(<a className={"dropdown-item"+(!index?" active":"")} href="#" onClick={(e) => this.changeProfile(e, profile)} key={index}>{profile.name||profile.username}</a>);
      });
    }
    if (profileList.length) {
      profileDropdown = 
      <div className="btn-group" role="group">
        <button className="btn btn-secondary dropdown-toggle" type="button" id="dropdownProfile" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
          <i className="fas fa-user"></i>
        </button>
        <div className="dropdown-menu" aria-labelledby="dropdownProfile">
          {profileList}
        </div>
      </div>
    }
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
          <div className="btn-group" role="group">
            <div className="btn-group" role="group">
              <button className="btn btn-secondary dropdown-toggle" type="button" id="dropdownLang" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                <i className="fas fa-globe-africa"></i>
              </button>
              <div className="dropdown-menu" aria-labelledby="dropdownLang">
                {langList}
              </div>
            </div>
            {profileDropdown}
            <button type="button" className="btn btn-secondary" onClick={this.toggleLogin}>
              <i className="fas fa-sign-in-alt btn-icon"></i>
            </button>
          </div>
        </form>
      </div>
    </nav>
		);
	}
}

export default Navbar;
