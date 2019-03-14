import React, { Component } from 'react';

class Edit extends Component {
  constructor(props) {
    super(props);

    this.state = {
      title: props.title,
      pattern: props.pattern,
      data: props.data,
      cb: props.callback,
      profile: props.profile,
      add: props.add,
      listAddValue: this.clearListAdd(props.pattern),
      listEltConfirm: this.clearListConfirm(props.pattern)
    }

    this.closeModal = this.closeModal.bind(this);
    this.editElt = this.editElt.bind(this);
    this.changeElt = this.changeElt.bind(this);
    this.toggleBooleanElt = this.toggleBooleanElt.bind(this);
    this.deleteListElt = this.deleteListElt.bind(this);
    this.createData = this.createData.bind(this);
    this.changeListAddElt = this.changeListAddElt.bind(this);
    this.AddListElt = this.AddListElt.bind(this);
    this.clearListAdd = this.clearListAdd.bind(this);
    this.clearListConfirm = this.clearListConfirm.bind(this);
    this.changeEltConfirm = this.changeEltConfirm.bind(this);

    if (this.state.add) {
      this.createData();
    }
  }

  componentWillReceiveProps(nextProps) {
    this.setState({
      title: nextProps.title,
      pattern: nextProps.pattern,
      data: nextProps.data,
      cb: nextProps.callback,
      profile: nextProps.profile,
      add: nextProps.add,
      listAddValue: this.clearListAdd(nextProps.pattern),
      listEltConfirm: this.clearListConfirm(nextProps.pattern)
    }, () => {
      if (nextProps.add) {
        this.createData();
      }
    });
  }

  closeModal(e, result) {
    if (this.state.cb) {
      this.state.cb(result, this.state.data);
    }
  }

  editElt(pattern, elt, key) {
    var labelJsx, inputJsx, listJsx = [];
    if (elt !== undefined || pattern.type === "password") {
      if (!this.state.profile || pattern.profile) {
        labelJsx = <label htmlFor={"modal-edit-" + pattern.name}>{i18next.t(pattern.label)}</label>;
        if (pattern.list) {
          elt.forEach((val, index) => {
            if (pattern.edit === false && !this.state.add) {
              listJsx.push(<span className="badge badge-primary" key={index}>{val}</span>);
            } else {
              listJsx.push(<a href="#" key={index} onClick={(e) => this.deleteListElt(e, pattern.name, index)}><span className="badge badge-primary">{val}</span></a>);
            }
          });
          if (!pattern.listElements) {
            inputJsx = <div className="input-group">
              <input type="text" className="form-control" id={"modal-edit-" + pattern.name} placeholder={i18next.t("modal.list-add-placeholder")} onChange={(e) => this.changeListAddElt(e, pattern.name)} value={this.state.listAddValue[pattern.name]}/>
              <div className="input-group-append">
                <button className="btn btn-outline-secondary" type="button" onClick={(e) => this.AddListElt(e, pattern.name)} title={i18next.t("modal.list-add-title")}>
                  <i className="fas fa-plus"></i>
                </button>
              </div>
            </div>
          } else {
            var listElements = [];
            pattern.listElements.forEach((element) => {
              listElements.push(<a className="dropdown-item" href="#" onClick={(e) => this.AddListElt(e, pattern.name, element)}>{element}</a>);
            });
            inputJsx = <div className="dropdown">
              <button className="btn btn-secondary btn-sm dropdown-toggle" type="button" id={"modal-edit-" + pattern.name} data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
                <i className="fas fa-plus"></i>
              </button>
              <div className="dropdown-menu" aria-labelledby={"modal-edit-" + pattern.name}>
                {listElements}
              </div>
            </div>
          }
        } else if (pattern.type === "boolean") {
          if (pattern.edit === false && !this.state.add) {
            inputJsx = <input disabled="true" type="checkbox" className="form-control" id={"modal-edit-" + pattern.name} checked={elt} />
          } else {
            inputJsx = <input type="checkbox" className="form-control" id={"modal-edit-" + pattern.name} onChange={(e) => this.toggleBooleanElt(e, pattern.name)} checked={elt} />
          }
        } else {
          if (pattern.edit === false && !this.state.add) {
            inputJsx = <input disabled="true" type={(pattern.type||"text")} className="form-control" id={"modal-edit-" + pattern.name} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""} value={elt}/>
          } else {
            if (pattern.type === "password") {
              inputJsx = <div><input type="password" className="form-control" id={"modal-edit-" + pattern.name} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""} value={elt} onChange={(e) => this.changeElt(e, pattern.name)}/><input type="password" className="form-control" id={"modal-edit-confirm" + pattern.name} placeholder={i18next.t(pattern.placeholderConfirm)} value={this.state.listEltConfirm[pattern.name]} onChange={(e) => this.changeEltConfirm(e, pattern.name)}/></div>
            } else {
              inputJsx = <input type={(pattern.type||"text")} className="form-control" id={"modal-edit-" + pattern.name} placeholder={pattern.placeholder?i18next.t(pattern.placeholder):""} value={elt} onChange={(e) => this.changeElt(e, pattern.name)}/>
            }
          }
        }
      }
    }
    return (
    <div className="form-group" key={key}>
      {labelJsx}
      <div>{listJsx}</div>
      {inputJsx}
    </div>);
  }

  deleteListElt(e, name, index) {
    var data = this.state.data;
    if (data[name]) {
      data[name].splice(index, 1);
      this.setState({data: data});
    }
  }

  changeElt(e, name) {
    var data = this.state.data;
    data[name] = e.target.value;
    this.setState({data: data});
  }

  toggleBooleanElt(e, name) {
    var data = this.state.data;
    data[name] = !data[name];
    this.setState({data: data});
  }

  createData() {
    var data = {};
    this.state.pattern.forEach((pat, index) => {
      if (pat.list) {
        data[pat.name] = [];
      } else {
        data[pat.name] = "";
      }
    });
    this.setState({data: data});
  }

  changeListAddElt(e, name) {
    var listAddValue = this.state.listAddValue;
    listAddValue[name] = e.target.value;
    this.setState({listAddValue: listAddValue});
  }

  AddListElt(e, name, value = false) {
    e.preventDefault();
    if (value) {
      var data = this.state.data;
      data[name].push(value);
      this.setState({data: data});
    } else {
      if (this.state.listAddValue[name]) {
        var data = this.state.data;
        var listAddValue = this.state.listAddValue;
        data[name].push(this.state.listAddValue[name]);
        this.state.listAddValue[name] = "";
        this.setState({data: data, listAddValue: listAddValue});
      }
    }
  }

  clearListAdd(patternList) {
    var listAddValue = {};
    patternList.forEach((pat) => {
      if (pat.list) {
        listAddValue[pat.name] = "";
      }
    });
    return listAddValue;
  }

  clearListConfirm(patternList) {
    var listEltConfirm = {};
    patternList.forEach((pat) => {
      if (pat.confirm) {
        listEltConfirm[pat.name] = "";
      }
    });
    return listEltConfirm;
  }

  changeEltConfirm(e, name) {
    var listEltConfirm = this.state.listEltConfirm;
    listEltConfirm[name] = e.target.value;
    this.setState({listEltConfirm: listEltConfirm});
  }
  
	render() {
    var editLines = [];
    this.state.pattern.forEach((pat, index) => {
      var line = this.editElt(pat, this.state.data[pat.name], index);
      if (line) {
        editLines.push(line);
      }
    });
		return (
    <div className="modal fade" id="editModal" tabIndex="-1" role="dialog" aria-labelledby="confirmModalLabel" aria-hidden="true">
      <div className="modal-dialog" role="document">
        <div className="modal-content">
          <div className="modal-header">
            <h5 className="modal-title" id="confirmModalLabel">{this.state.title}</h5>
            <button type="button" className="close" aria-label={i18next.t("modal.close")} onClick={(e) => this.closeModal(e, false)}>
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div className="modal-body">
            <form>
              {editLines}
            </form>
          </div>
          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={(e) => this.closeModal(e, false)}>{i18next.t("modal.close")}</button>
            <button type="button" className="btn btn-primary" onClick={(e) => this.closeModal(e, true)}>{i18next.t("modal.ok")}</button>
          </div>
        </div>
      </div>
    </div>
		);
	}
}

export default Edit;
