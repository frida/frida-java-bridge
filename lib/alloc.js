class CodeAllocator {
  constructor (sliceSize) {
    this.sliceSize = sliceSize;
    this.slicesPerPage = Process.pageSize / sliceSize;

    this.pages = [];
    this.free = [];
  }

  allocateSlice () {
    const slice = this.free.pop();
    if (slice !== undefined) {
      return slice;
    }

    return this._allocatePage();
  }

  allocateSliceNear (address, maxDistance) {
    const { free } = this;

    for (let i = 0; i !== free.length; i++) {
      const slice = free[i];
      if (this._isSliceNear(slice, address, maxDistance)) {
        return free.splice(i, 1);
      }
    }

    return this._allocatePage({ nearAddress: address, maxDistance });
  }

  _allocatePage (spec = null) {
    const pageSize = Process.pageSize;

    let page;
    if (spec === null) {
      page = Memory.alloc(pageSize);
    } else {
      const { nearAddress, maxDistance } = spec;
      page = Memory.allocNear(pageSize, nearAddress, maxDistance);
    }

    const { sliceSize, slicesPerPage } = this;

    for (let i = 1; i !== slicesPerPage; i++) {
      const slice = page.add(i * sliceSize);
      this.free.push(slice);
    }

    this.pages.push(page);

    return page;
  }

  _isSliceNear (slice, address, maxDistance) {
    const sliceEnd = slice.add(this.sliceSize);

    const startDistance = int64(abs(address.sub(slice)).toString());
    const endDistance = int64(abs(address.sub(sliceEnd)).toString());

    return startDistance.compare(maxDistance) <= 0 &&
        endDistance.compare(maxDistance) <= 0;
  }

  freeSlice (slice) {
    this.free.push(slice);
  }
}

function abs(nptr) {
  const pointerSize = Process.pointerSize;
  const shmt = pointerSize === 4 ? 31 : 63;
  const mask = ptr(1).shl(shmt).not();
  return nptr.and(mask);
}

function makeAllocator (sliceSize) {
  return new CodeAllocator(sliceSize);
}

module.exports = makeAllocator;
